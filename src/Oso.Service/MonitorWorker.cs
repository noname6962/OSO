// Spina trzy moduły. Kolektor zapisuje do kolejki, analizator ją odczytuje, a osobna pętla dostarcza zapisane alerty. Obsługuje zatrzymanie i błędy pętli. Usuwa stare zdarzenia z pamięci również wtedy, gdy nie pojawiają się nowe.

using System.Threading.Channels;
using Oso.Core;

namespace Oso.Service;

/// <summary>
/// Runs the three modules inside one Windows Service: collect -> analyze -> persist/deliver.
/// Separate async loops let monitoring continue while Gmail is unavailable or an email is being sent.
/// </summary>
public sealed class MonitorWorker(WindowsCollector collector, LoginAnalyzer analyzer,
    DurableReporter reporter, ReportingOptions options, ILogger<MonitorWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // One cancellation source stops all loops when Windows stops the service or a loop fails.
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        // This queue connects Module 1 to Module 2. FullMode.Wait slows the producer when full.
        var channel = Channel.CreateBounded<LoginEvent>(new BoundedChannelOptions(4096)
        {
            FullMode = BoundedChannelFullMode.Wait, SingleReader = true, SingleWriter = true
        });
        // Start collection, analysis and delivery; await coordinates their lifetimes without busy waiting.
        var tasks = new[] { Collect(), Analyze(), Deliver() };
        try
        {
            // Any unexpected pipeline exit stops the whole service instead of leaving it partly alive.
            await Task.WhenAny(tasks);
            stop.Cancel();
            await Task.WhenAll(tasks);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        catch (Exception ex)
        {
            logger.LogCritical(ex, "Login monitor stopped. Check Security access, storage and configuration.");
            // A nonzero exit lets the Windows service recovery policy restart the process.
            Environment.ExitCode = 1;
            throw;
        }

        // MODULE 1: complete the output queue when the collector stops so analysis is not left waiting.
        async Task Collect()
        {
            try { await collector.RunAsync(channel.Writer, stop.Token); }
            finally { channel.Writer.TryComplete(); }
        }
        // MODULE 2: one consumer owns the analyzer's history; no concurrent access to that history.
        async Task Analyze()
        {
            // An idle timer expires history even when no new events arrive.
            while (!stop.IsCancellationRequested)
            {
                using var wait = CancellationTokenSource.CreateLinkedTokenSource(stop.Token);
                wait.CancelAfter(TimeSpan.FromSeconds(5));
                try
                {
                    if (!await channel.Reader.WaitToReadAsync(wait.Token)) break;
                }
                // A five-second idle timeout means "prune history", not "stop the service".
                catch (OperationCanceledException) when (!stop.IsCancellationRequested) { }
                analyzer.Prune(DateTimeOffset.UtcNow);
                while (channel.Reader.TryRead(out var item))
                {
                    var alert = analyzer.Process(item, DateTimeOffset.UtcNow);
                    // Save alerts to disk here; Gmail work happens in Deliver(), not in this loop.
                    if (alert is not null && await reporter.AcceptAsync(alert, stop.Token))
                        logger.LogInformation("Queued alert {AlertId} from Security record {RecordId}.", alert.Id, item.RecordId);
                }
            }
        }
        // MODULE 3: periodically send queued alerts whose initial/retry time has arrived.
        async Task Deliver()
        {
            while (!stop.IsCancellationRequested)
            {
                await reporter.ProcessPendingAsync(stop.Token);
                await Task.Delay(TimeSpan.FromSeconds(options.RetryPollSeconds), stop.Token);
            }
        }
    }
}
