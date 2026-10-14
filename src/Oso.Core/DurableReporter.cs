using System.Text.Json;

namespace Oso.Core;

public interface IWarningSink
{
    Task WriteAsync(string entry, CancellationToken cancellationToken);
}

public interface IEmailSink
{
    Task SendAsync(SecurityAlert alert, CancellationToken cancellationToken);
}

public sealed record DeliveryRecord(string Id, DateTimeOffset EventTime, SecurityAlert? Alert,
    int WarningPartsWritten = 0, int Attempts = 0, DateTimeOffset? NextAttempt = null,
    DateTimeOffset? CompletedAt = null);

public sealed class FileOutbox
{
    private readonly string directory;
    private readonly SemaphoreSlim gate = new(1, 1);
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public FileOutbox(string directory)
    {
        this.directory = directory;
        Directory.CreateDirectory(directory);
    }

    private string PathFor(string id)
    {
        if (id.Length != 64 || id.Any(c => !Uri.IsHexDigit(c))) throw new ArgumentException("Invalid alert ID.");
        return Path.Combine(directory, id + ".json");
    }

    public async Task<bool> AcceptAsync(SecurityAlert alert, CancellationToken ct = default)
    {
        await gate.WaitAsync(ct);
        try
        {
            if (File.Exists(PathFor(alert.Id))) return false;
            await SaveUnlocked(new DeliveryRecord(alert.Id, alert.Trigger.Timestamp, alert), ct);
            return true;
        }
        finally { gate.Release(); }
    }

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
        File.Move(temp, target, overwrite: true);
    }

    public async Task SaveAsync(DeliveryRecord record, CancellationToken ct = default)
    {
        await gate.WaitAsync(ct);
        try { await SaveUnlocked(record, ct); }
        finally { gate.Release(); }
    }

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
                if (PathFor(record.Id) != path) throw new InvalidDataException("Outbox record identity mismatch.");
                records.Add(record);
            }
            return records.OrderBy(r => r.EventTime).ThenBy(r => r.Id).ToArray();
        }
        finally { gate.Release(); }
    }

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

public sealed class DurableReporter(FileOutbox outbox, IWarningSink warnings, IEmailSink email,
    TimeProvider? clock = null, Action<string, Exception>? onError = null)
{
    private readonly TimeProvider time = clock ?? TimeProvider.System;
    private readonly SemaphoreSlim pump = new(1, 1);

    public Task<bool> AcceptAsync(SecurityAlert alert, CancellationToken ct = default) => outbox.AcceptAsync(alert, ct);

    public async Task ProcessPendingAsync(CancellationToken ct = default)
    {
        await pump.WaitAsync(ct);
        try
        {
            foreach (var initial in await outbox.ReadAsync(ct))
            {
                if (initial.CompletedAt != null || initial.NextAttempt > time.GetUtcNow()) continue;
                var record = initial;
                var alert = record.Alert ?? throw new InvalidDataException("Pending record has no evidence.");
                try
                {
                    var entries = AlertFormatter.WarningEntries(alert);
                    for (var i = record.WarningPartsWritten; i < entries.Count; i++)
                    {
                        await warnings.WriteAsync(entries[i], ct);
                        record = record with { WarningPartsWritten = i + 1 };
                        await outbox.SaveAsync(record, ct);
                    }
                    await email.SendAsync(alert, ct);
                    await outbox.SaveAsync(record with
                    {
                        Alert = null, CompletedAt = time.GetUtcNow(), NextAttempt = null
                    }, ct);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception ex)
                {
                    onError?.Invoke($"Delivery failed for alert {record.Id}; retained for retry.", ex);
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
