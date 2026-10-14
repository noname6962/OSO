using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using Oso.Core;
using Oso.Service;

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("OSO service requires Windows. Run the Oso.Tests project for platform-independent validation.");
    return 1;
}

try
{
    var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
    {
        Args = args, ContentRootPath = AppContext.BaseDirectory
    });
    builder.Configuration.AddJsonFile("appsettings.Local.json", optional: true, reloadOnChange: false)
        .AddEnvironmentVariables("OSO_");
    var detection = builder.Configuration.GetSection("Detection").Get<DetectionOptions>() ?? new();
    var reporting = builder.Configuration.GetSection("Reporting").Get<ReportingOptions>() ?? new();
    var smtp = builder.Configuration.GetSection("Smtp").Get<SmtpOptions>() ?? new();
    detection.Validate(); reporting.Validate(); smtp.Validate();
    var dataDirectory = Environment.ExpandEnvironmentVariables(reporting.DataDirectory);
    if (!Path.IsPathFullyQualified(dataDirectory)) throw new ArgumentException("Reporting.DataDirectory must be an absolute path.");
    if (!File.Exists(Environment.ExpandEnvironmentVariables(smtp.PasswordFile)))
        throw new FileNotFoundException("Encrypted Gmail password file missing. Run Set-GmailCredential.ps1.");
    GmailEmailSink.ValidateCredential(smtp);
    if (!EventLog.SourceExists(reporting.SourceName) ||
        !EventLog.LogNameFromSourceName(reporting.SourceName, ".").Equals(reporting.LogName, StringComparison.OrdinalIgnoreCase))
        throw new InvalidOperationException("Warning source is missing or registered to another log. Run Install-Service.ps1.");
    using (var reader = new EventLogReader(new EventLogQuery("Security", PathType.LogName, "*[System[EventID=4624]]") { ReverseDirection = true }))
    using (reader.ReadEvent()) { } // Access check, not a functional readiness claim.

    if (args.Contains("--validate-config", StringComparer.Ordinal))
    {
        Console.WriteLine("Configuration, credential decryption, warning source and Security log read access checked.");
        return 0;
    }

    Directory.CreateDirectory(dataDirectory);
    using var instanceLock = new FileStream(Path.Combine(dataDirectory, "monitor.lock"),
        FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
    builder.Services.AddWindowsService(o => o.ServiceName = "OsoLoginMonitor");
    builder.Logging.AddEventLog(o => { o.LogName = reporting.LogName; o.SourceName = reporting.SourceName; });
    builder.Services.Configure<HostOptions>(o => o.ShutdownTimeout = TimeSpan.FromSeconds(45));
    builder.Services.AddSingleton(detection);
    builder.Services.AddSingleton(reporting);
    builder.Services.AddSingleton(smtp);
    builder.Services.AddSingleton<LoginAnalyzer>();
    builder.Services.AddSingleton<WindowsCollector>();
    builder.Services.AddSingleton(new FileOutbox(Path.Combine(dataDirectory, "outbox")));
    builder.Services.AddSingleton<IWarningSink, WindowsWarningSink>();
    builder.Services.AddSingleton<IEmailSink, GmailEmailSink>();
    builder.Services.AddSingleton(provider => new DurableReporter(provider.GetRequiredService<FileOutbox>(),
        provider.GetRequiredService<IWarningSink>(), provider.GetRequiredService<IEmailSink>(),
        onError: (message, ex) => provider.GetRequiredService<ILogger<DurableReporter>>().LogError(ex, "{Message}", message)));
    builder.Services.AddHostedService<MonitorWorker>();
    using var host = builder.Build();
    await host.RunAsync();
    return Environment.ExitCode;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"OSO startup/runtime failure: {ex.Message}");
    return 1;
}
