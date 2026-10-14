using System.Threading.Channels;
using Oso.Core;

namespace Oso.Service;

public sealed class MonitorWorker(WindowsCollector collector, LoginAnalyzer analyzer,
    DurableReporter reporter, ReportingOptions options, ILogger<MonitorWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        var channel = Channel.CreateBounded<LoginEvent>(new BoundedChannelOptions(4096)
        {
            FullMode = BoundedChannelFullMode.Wait, SingleReader = true, SingleWriter = true
        });
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

        async Task Collect()
        {
            try { await collector.RunAsync(channel.Writer, stop.Token); }
            finally { channel.Writer.TryComplete(); }
        }
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
                catch (OperationCanceledException) when (!stop.IsCancellationRequested) { }
                analyzer.Prune(DateTimeOffset.UtcNow);
                while (channel.Reader.TryRead(out var item))
                {
                    var alert = analyzer.Process(item, DateTimeOffset.UtcNow);
                    if (alert is not null && await reporter.AcceptAsync(alert, stop.Token))
                        logger.LogInformation("Queued alert {AlertId} from Security record {RecordId}.", alert.Id, item.RecordId);
                }
            }
        }
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
