using System.Text.Json;

namespace Oso.Core;

/// <summary>Module 3's destination for one formatted Windows warning entry.</summary>
public interface IWarningSink
{
    Task WriteAsync(string entry, CancellationToken cancellationToken);
}

/// <summary>Module 3's destination for one email containing an alert and its evidence.</summary>
public interface IEmailSink
{
    Task SendAsync(SecurityAlert alert, CancellationToken cancellationToken);
}

/// <summary>
/// On-disk delivery state for an alert. WarningPartsWritten tracks completed log entries;
/// Attempts/NextAttempt control retries. After email delivery, Alert becomes null to remove
/// the evidence payload, while Id/CompletedAt remain as a temporary replay-deduplication marker.
/// </summary>
public sealed record DeliveryRecord(string Id, DateTimeOffset EventTime, SecurityAlert? Alert,
    int WarningPartsWritten = 0, int Attempts = 0, DateTimeOffset? NextAttempt = null,
    DateTimeOffset? CompletedAt = null);

/// <summary>
/// Module 3 persistence: one JSON file per alert, kept across service restarts.
/// Pending evidence must reach disk before the analyzer moves on to the next event.
/// </summary>
public sealed class FileOutbox
{
    private readonly string directory;
    // Allow one file operation at a time: analysis and delivery run concurrently.
    // Program.cs also holds a process-wide file lock to prevent two service instances.
    private readonly SemaphoreSlim gate = new(1, 1);
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public FileOutbox(string directory)
    {
        this.directory = directory;
        Directory.CreateDirectory(directory);
    }

    private string PathFor(string id)
    {
        // IDs are SHA-256 hex strings, not arbitrary filenames or paths.
        if (id.Length != 64 || id.Any(c => !Uri.IsHexDigit(c))) throw new ArgumentException("Invalid alert ID.");
        return Path.Combine(directory, id + ".json");
    }

    /// <summary>Persist a new alert; return false if the same triggering record is already known.</summary>
    public async Task<bool> AcceptAsync(SecurityAlert alert, CancellationToken ct = default)
    {
        await gate.WaitAsync(ct);
        try
        {
            // Existing files can represent pending deliveries or recently completed deliveries.
            if (File.Exists(PathFor(alert.Id))) return false;
            await SaveUnlocked(new DeliveryRecord(alert.Id, alert.Trigger.Timestamp, alert), ct);
            return true;
        }
        finally { gate.Release(); }
    }

    // Caller must hold gate. Write a temporary file and replace the committed JSON only when ready.
    private async Task SaveUnlocked(DeliveryRecord record, CancellationToken ct)
    {
        var target = PathFor(record.Id);
        var temp = target + ".tmp";
        // Flush before atomic replacement so a restart never observes half a JSON record.
        await using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            await JsonSerializer.SerializeAsync(stream, record, Json, ct);
            await stream.FlushAsync(ct);
            stream.Flush(flushToDisk: true);
        }
        // Readers enumerate only *.json, so an interrupted *.json.tmp write is never treated as an alert.
        File.Move(temp, target, overwrite: true);
    }

    /// <summary>Persist progress after a warning part, failed attempt or completed email.</summary>
    public async Task SaveAsync(DeliveryRecord record, CancellationToken ct = default)
    {
        await gate.WaitAsync(ct);
        try { await SaveUnlocked(record, ct); }
        finally { gate.Release(); }
    }

    /// <summary>Read committed delivery records in event-time order; invalid state fails visibly.</summary>
    public async Task<IReadOnlyList<DeliveryRecord>> ReadAsync(CancellationToken ct = default)
    {
        await gate.WaitAsync(ct);
        try
        {
            var records = new List<DeliveryRecord>();
            foreach (var path in Directory.EnumerateFiles(directory, "*.json"))
            {
                await using var stream = File.OpenRead(path);
                var record = await JsonSerializer.DeserializeAsync<DeliveryRecord>(stream, Json, ct)
                    ?? throw new InvalidDataException($"Empty delivery record: {Path.GetFileName(path)}");
                // A mismatched filename/ID could cause an alert to be overwritten or delivered incorrectly.
                if (PathFor(record.Id) != path) throw new InvalidDataException("Outbox record identity mismatch.");
                records.Add(record);
            }
            return records.OrderBy(r => r.EventTime).ThenBy(r => r.Id).ToArray();
        }
        finally { gate.Release(); }
    }

    /// <summary>Remove old completed delivery markers; never remove undelivered evidence or Windows logs.</summary>
    public async Task PruneCompletedAsync(DateTimeOffset now, CancellationToken ct = default)
    {
        await gate.WaitAsync(ct);
        try
        {
            foreach (var path in Directory.EnumerateFiles(directory, "*.json"))
            {
                var record = JsonSerializer.Deserialize<DeliveryRecord>(await File.ReadAllTextAsync(path, ct), Json)
                    ?? throw new InvalidDataException("Empty delivery record.");
                // Delivered records retain identity only; pending evidence is never discarded.
                if (record.CompletedAt is not null && record.EventTime < now.AddHours(-24)) File.Delete(path);
            }
        }
        finally { gate.Release(); }
    }
}

/// <summary>
/// Module 3 coordinator: write warnings first, then email, remembering progress for retries.
/// Collection/analysis only enqueue alerts; the worker calls ProcessPendingAsync separately.
/// </summary>
public sealed class DurableReporter(FileOutbox outbox, IWarningSink warnings, IEmailSink email,
    TimeProvider? clock = null, Action<string, Exception>? onError = null)
{
    // A clock abstraction supplies UTC time for retry scheduling.
    private readonly TimeProvider time = clock ?? TimeProvider.System;
    // Only one delivery pass may run at once, avoiding simultaneous sends of the same alert.
    private readonly SemaphoreSlim pump = new(1, 1);

    /// <summary>Save an analyzer alert without waiting for Gmail or Windows warning delivery.</summary>
    public Task<bool> AcceptAsync(SecurityAlert alert, CancellationToken ct = default) => outbox.AcceptAsync(alert, ct);

    /// <summary>Deliver all currently due alerts, persisting progress and rescheduling ordinary failures.</summary>
    public async Task ProcessPendingAsync(CancellationToken ct = default)
    {
        await pump.WaitAsync(ct);
        try
        {
            foreach (var initial in await outbox.ReadAsync(ct))
            {
                // Completed alerts and alerts still waiting for their retry time need no work now.
                if (initial.CompletedAt != null || initial.NextAttempt > time.GetUtcNow()) continue;
                var record = initial;
                var alert = record.Alert ?? throw new InvalidDataException("Pending record has no evidence.");
                try
                {
                    var entries = AlertFormatter.WarningEntries(alert);
                    // Resume at the first unwritten part, rather than rewriting the whole warning.
                    for (var i = record.WarningPartsWritten; i < entries.Count; i++)
                    {
                        await warnings.WriteAsync(entries[i], ct);
                        record = record with { WarningPartsWritten = i + 1 };
                        await outbox.SaveAsync(record, ct);
                    }
                    // Email is attempted only after all warning parts were written successfully.
                    // External writes and JSON updates are separate operations: a crash between them
                    // can still produce a duplicate. This is at-least-once delivery, not exactly-once.
                    await email.SendAsync(alert, ct);
                    await outbox.SaveAsync(record with
                    {
                        // Drop the potentially large evidence payload, retaining only delivery metadata.
                        Alert = null, CompletedAt = time.GetUtcNow(), NextAttempt = null
                    }, ct);
                }
                // Service shutdown is not a delivery failure; leave the record for the next startup.
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception ex)
                {
                    onError?.Invoke($"Delivery failed for alert {record.Id}; retained for retry.", ex);
                    // Back off for 15, 30, 60, 120, 240, then 300 seconds; pending evidence stays on disk.
                    var attempts = record.Attempts + 1;
                    await outbox.SaveAsync(record with
                    {
                        Attempts = attempts,
                        NextAttempt = time.GetUtcNow().AddSeconds(Math.Min(300, 15 * Math.Pow(2, Math.Min(attempts - 1, 5))))
                    }, ct);
                }
            }
            await outbox.PruneCompletedAsync(time.GetUtcNow(), ct);
        }
        finally { pump.Release(); }
    }
}
