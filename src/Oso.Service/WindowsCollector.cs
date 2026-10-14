using System.Diagnostics.Eventing.Reader;
using System.Threading.Channels;
using Oso.Core;

namespace Oso.Service;

public sealed class WindowsCollector(DetectionOptions options, ILogger<WindowsCollector> logger)
{
    public async Task RunAsync(ChannelWriter<LoginEvent> output, CancellationToken ct)
    {
        var live = Channel.CreateBounded<LoginEvent>(new BoundedChannelOptions(4096)
        {
            FullMode = BoundedChannelFullMode.Wait, SingleReader = true, SingleWriter = false
        });
        var ids = string.Join(" or ", EventParser.SupportedIds.Select(id => $"EventID={id}"));
        var query = new EventLogQuery("Security", PathType.LogName, $"*[System[({ids})]]");
        using var watcher = new EventLogWatcher(query);
        watcher.EventRecordWritten += (_, args) =>
        {
            if (args.EventException != null)
            {
                live.Writer.TryComplete(args.EventException);
                return;
            }
            using var record = args.EventRecord;
            if (record is null) return;
            try
            {
                var item = EventParser.Parse(record.ToXml());
                // Backpressure instead of silently dropping authentication events.
                live.Writer.WriteAsync(item, ct).AsTask().GetAwaiter().GetResult();
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
            catch (ChannelClosedException) { }
            catch (Exception ex) when (ex is FormatException or System.Xml.XmlException or ArgumentException or OverflowException)
            { logger.LogWarning(ex, "Skipped malformed Security event record {RecordId}.", record.RecordId); }
            catch (Exception ex) { live.Writer.TryComplete(ex); }
        };
        try
        {
            watcher.Enabled = true;
            var millis = (long)TimeSpan.FromMinutes(options.StartupLookbackMinutes).TotalMilliseconds;
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
