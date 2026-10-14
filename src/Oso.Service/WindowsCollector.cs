using System.Diagnostics.Eventing.Reader;
using System.Threading.Channels;
using Oso.Core;

namespace Oso.Service;

/// <summary>
/// Module 1: reads recent local Security history and subscribes to newly written records.
/// Parsed LoginEvent objects leave through the output queue consumed by Module 2.
/// </summary>
public sealed class WindowsCollector(DetectionOptions options, ILogger<WindowsCollector> logger)
{
    /// <summary>Replay startup history, then keep forwarding live records until stopped or a subscription fails.</summary>
    public async Task RunAsync(ChannelWriter<LoginEvent> output, CancellationToken ct)
    {
        // Keep new events buffered while historical events are being read.
        // A bounded queue waits when full rather than growing indefinitely or dropping records.
        var live = Channel.CreateBounded<LoginEvent>(new BoundedChannelOptions(4096)
        {
            FullMode = BoundedChannelFullMode.Wait, SingleReader = true, SingleWriter = false
        });
        // Windows Event Log accepts an XPath filter; request only our five supported IDs.
        var ids = string.Join(" or ", EventParser.SupportedIds.Select(id => $"EventID={id}"));
        var query = new EventLogQuery("Security", PathType.LogName, $"*[System[({ids})]]");
        using var watcher = new EventLogWatcher(query);
        watcher.EventRecordWritten += (_, args) =>
        {
            // A subscription failure ends the queue with an error so the worker can stop/recover.
            if (args.EventException != null)
            {
                live.Writer.TryComplete(args.EventException);
                return;
            }
            // EventRecord owns a native Windows handle. Dispose it after copying its XML.
            using var record = args.EventRecord;
            if (record is null) return;
            try
            {
                var item = EventParser.Parse(record.ToXml());
                // The Windows callback is synchronous. Wait for queue space; the downstream
                // async consumer drains it, and cancellation releases the wait on shutdown.
                live.Writer.WriteAsync(item, ct).AsTask().GetAwaiter().GetResult();
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
            catch (ChannelClosedException) { }
            // One malformed record is reported and skipped; other collector failures stop monitoring.
            catch (Exception ex) when (ex is FormatException or System.Xml.XmlException or ArgumentException or OverflowException)
            { logger.LogWarning(ex, "Skipped malformed Security event record {RecordId}.", record.RecordId); }
            catch (Exception ex) { live.Writer.TryComplete(ex); }
        };
        try
        {
            // Subscribe BEFORE reading history to avoid a gap where a new event could be missed.
            watcher.Enabled = true;
            var millis = (long)TimeSpan.FromMinutes(options.StartupLookbackMinutes).TotalMilliseconds;
            // timediff is in milliseconds. ReverseDirection=false reads oldest to newest,
            // allowing the analyzer to reconstruct failure patterns in their original order.
            var historyQuery = new EventLogQuery("Security", PathType.LogName,
                $"*[System[({ids}) and TimeCreated[timediff(@SystemTime) <= {millis}]]]") { ReverseDirection = false };
            using (var reader = new EventLogReader(historyQuery))
            {
                while (!ct.IsCancellationRequested)
                {
                    using var record = reader.ReadEvent();
                    if (record is null) break;
                    LoginEvent item;
                    try { item = EventParser.Parse(record.ToXml()); }
                    catch (Exception ex) when (ex is FormatException or System.Xml.XmlException or ArgumentException or OverflowException)
                    {
                        logger.LogWarning(ex, "Skipped malformed historical record {RecordId}.", record.RecordId);
                        continue;
                    }
                    await output.WriteAsync(item, ct);
                }
            }
            logger.LogInformation("Startup replay completed; monitoring Security log.");
            // History/live overlap is expected; LoginAnalyzer deduplicates by event identity.
            // After replay, this loop waits for new events without polling the Security log.
            await foreach (var item in live.Reader.ReadAllAsync(ct)) await output.WriteAsync(item, ct);
        }
        finally
        {
            // Unblock callbacks before disposing the subscription.
            live.Writer.TryComplete();
            watcher.Enabled = false;
        }
    }
}
