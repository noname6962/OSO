using System.Diagnostics;
using Oso.Core;

namespace Oso.Service;

public sealed class WindowsWarningSink(ReportingOptions options) : IWarningSink
{
    public Task WriteAsync(string entry, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EventLog.WriteEntry(options.SourceName, entry, EventLogEntryType.Warning, 1000);
        return Task.CompletedTask;
    }
}
