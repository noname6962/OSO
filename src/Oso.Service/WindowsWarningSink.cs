// Zapisuje przygotowaną treść do źródła `OsoLoginMonitor`, przypisanego do dziennika `OSO-Warnings`. Ostrzeżenia mają ID 1000.

using System.Diagnostics;
using Oso.Core;

namespace Oso.Service;

/// <summary>Module 3 Windows adapter: writes formatted alerts to the source registered by the installer.</summary>
public sealed class WindowsWarningSink(ReportingOptions options) : IWarningSink
{
    public Task WriteAsync(string entry, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // SourceName determines the destination log through Windows source registration.
        // ID 1000 identifies alert evidence; ordinary service diagnostics use separate event IDs.
        EventLog.WriteEntry(options.SourceName, entry, EventLogEntryType.Warning, 1000);
        return Task.CompletedTask;
    }
}
