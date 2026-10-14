using MimeKit;

namespace Oso.Service;

public sealed class ReportingOptions
{
    public string LogName { get; set; } = "OSO-Warnings";
    public string SourceName { get; set; } = "OsoLoginMonitor";
    public string DataDirectory { get; set; } = "%ProgramData%\\OSO";
    public int RetryPollSeconds { get; set; } = 5;

    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(LogName) || string.IsNullOrWhiteSpace(SourceName) ||
            string.IsNullOrWhiteSpace(DataDirectory) || RetryPollSeconds < 1)
            throw new ArgumentException("Invalid Reporting configuration.");
        if (LogName.Equals("Security", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Warnings must not be written to Security.");
    }
}

public sealed class SmtpOptions
{
    public string Host { get; set; } = "smtp.gmail.com";
    public int Port { get; set; } = 587;
    public string Username { get; set; } = "";
    public string Recipient { get; set; } = "";
    public string PasswordFile { get; set; } = "%ProgramData%\\OSO\\gmail-password.bin";

    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Host) || Port is < 1 or > 65535 ||
            !MailboxAddress.TryParse(Username, out _) || !MailboxAddress.TryParse(Recipient, out _) ||
            string.IsNullOrWhiteSpace(PasswordFile))
            throw new ArgumentException("Configure a valid SMTP host, port, Gmail username, recipient and encrypted password file.");
    }
}
