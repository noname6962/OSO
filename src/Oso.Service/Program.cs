// Punkt wejścia. Wczytuje konfigurację, sprawdza dostęp do Security, rejestrację dziennika ostrzeżeń i możliwość odszyfrowania hasła. Rejestruje zależności, zakłada blokadę drugiej instancji i uruchamia usługę. Obsługuje też `--validate-config`.

using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using Oso.Core;
using Oso.Service;

// APPLICATION ENTRY POINT: validate configuration, connect the module dependencies,
// then let the .NET host manage Windows Service startup and shutdown.
// The source can compile on Linux, but its collector, Event Log writer and DPAPI need Windows.
if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("OSO service requires Windows. Build or publish on Linux, then run the executable on Windows.");
    return 1;
}

try
{
    // Windows Services may start with System32 as their working directory.
    // Resolve configuration beside the executable instead of depending on the caller's directory.
    var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
    {
        Args = args, ContentRootPath = AppContext.BaseDirectory
    });
    // Override order: standard appsettings, installed local settings, then OSO_ environment variables.
    // Example: OSO_Detection__FailureThreshold overrides Detection.FailureThreshold.
    builder.Configuration.AddJsonFile("appsettings.Local.json", optional: true, reloadOnChange: false)
        .AddEnvironmentVariables("OSO_");
    // Bind configuration sections to typed objects and reject unusable values before monitoring starts.
    // These objects are loaded once; restart the service after changing settings.
    var detection = builder.Configuration.GetSection("Detection").Get<DetectionOptions>() ?? new();
    var reporting = builder.Configuration.GetSection("Reporting").Get<ReportingOptions>() ?? new();
    var smtp = builder.Configuration.GetSection("Smtp").Get<SmtpOptions>() ?? new();
    detection.Validate(); reporting.Validate(); smtp.Validate();
    // Expand placeholders such as %ProgramData%, keeping delivery state outside the application folder.
    var dataDirectory = Environment.ExpandEnvironmentVariables(reporting.DataDirectory);
    if (!Path.IsPathFullyQualified(dataDirectory)) throw new ArgumentException("Reporting.DataDirectory must be an absolute path.");
    if (!File.Exists(Environment.ExpandEnvironmentVariables(smtp.PasswordFile)))
        throw new FileNotFoundException("Encrypted Gmail password file missing. Run Set-GmailCredential.ps1.");
    // Check local credential decryption and source registration now, rather than discovering
    // these installation problems only after the first suspicious login.
    GmailEmailSink.ValidateCredential(smtp);
    if (!EventLog.SourceExists(reporting.SourceName) ||
        !EventLog.LogNameFromSourceName(reporting.SourceName, ".").Equals(reporting.LogName, StringComparison.OrdinalIgnoreCase))
        throw new InvalidOperationException("Warning source is missing or registered to another log. Run Install-Service.ps1.");
    // Opening the Security reader checks access. A machine with no matching record can still
    // pass this check; it does not prove auditing or live subscription is working.
    using (var reader = new EventLogReader(new EventLogQuery("Security", PathType.LogName, "*[System[EventID=4624]]") { ReverseDirection = true }))
    using (reader.ReadEvent()) { } // Access check, not a functional readiness claim.

    // Installer preflight mode performs the checks above and exits without launching the modules.
    if (args.Contains("--validate-config", StringComparer.Ordinal))
    {
        Console.WriteLine("Configuration, credential decryption, warning source and Security log read access checked.");
        return 0;
    }

    Directory.CreateDirectory(dataDirectory);
    // Hold an exclusive handle until process shutdown. A second instance using the same
    // state directory cannot start and race the first instance's outbox writes/sends.
    using var instanceLock = new FileStream(Path.Combine(dataDirectory, "monitor.lock"),
        FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
    // Integrate host lifecycle with Windows Service Control Manager and send diagnostics to our log.
    builder.Services.AddWindowsService(o => o.ServiceName = "OsoLoginMonitor");
    builder.Logging.AddEventLog(o => { o.LogName = reporting.LogName; o.SourceName = reporting.SourceName; });
    builder.Services.Configure<HostOptions>(o => o.ShutdownTimeout = TimeSpan.FromSeconds(45));
    // Dependency injection: the host constructs classes using these registered dependencies.
    // Singleton means one shared instance for this process, important for history and outbox state.
    builder.Services.AddSingleton(detection);
    builder.Services.AddSingleton(reporting);
    builder.Services.AddSingleton(smtp);
    // Module 2 and Module 1 respectively; their constructor settings/loggers are injected automatically.
    builder.Services.AddSingleton<LoginAnalyzer>();
    builder.Services.AddSingleton<WindowsCollector>();
    // Module 3: file persistence plus concrete Windows/Gmail implementations of the sink interfaces.
    builder.Services.AddSingleton(new FileOutbox(Path.Combine(dataDirectory, "outbox")));
    builder.Services.AddSingleton<IWarningSink, WindowsWarningSink>();
    builder.Services.AddSingleton<IEmailSink, GmailEmailSink>();
    // Build the reporting coordinator and route retry errors through normal service diagnostics.
    builder.Services.AddSingleton(provider => new DurableReporter(provider.GetRequiredService<FileOutbox>(),
        provider.GetRequiredService<IWarningSink>(), provider.GetRequiredService<IEmailSink>(),
        onError: (message, ex) => provider.GetRequiredService<ILogger<DurableReporter>>().LogError(ex, "{Message}", message)));
    // MonitorWorker owns the three running loops. RunAsync waits until shutdown;
    // the worker sets a nonzero exit code on fatal failures so Windows recovery can restart it.
    builder.Services.AddHostedService<MonitorWorker>();
    using var host = builder.Build();
    await host.RunAsync();
    return Environment.ExitCode;
}
catch (Exception ex)
{
    // Configuration/startup failures can happen before the normal logger exists.
    // Report them to stderr and return a failing process exit code.
    Console.Error.WriteLine($"OSO startup/runtime failure: {ex.Message}");
    return 1;
}
