// Klasy ustawień zapisu ostrzeżeń i SMTP oraz sprawdzanie ich poprawności. Nie przechowuje hasła wprost — tylko ścieżkę do zaszyfrowanego pliku.

using MimeKit;

namespace Oso.Service;

/// <summary>Settings for Module 3's Windows warning destination and persistent delivery state.</summary>
public sealed class ReportingOptions
{
    // LogName is the container visible in Event Viewer; SourceName is its registered writer identity.
    public string LogName { get; set; } = "OSO-Warnings";
    public string SourceName { get; set; } = "OsoLoginMonitor";
    // The installer restricts this folder to SYSTEM and Administrators; outbox files live beneath it.
    public string DataDirectory { get; set; } = "%ProgramData%\\OSO";
    // How often the delivery loop checks for new alerts and retries that have become due.
    public int RetryPollSeconds { get; set; } = 5;

    /// <summary>Ensure a usable destination and avoid writing our own warnings back into Security.</summary>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(LogName) || string.IsNullOrWhiteSpace(SourceName) ||
            string.IsNullOrWhiteSpace(DataDirectory) || RetryPollSeconds < 1)
            throw new ArgumentException("Invalid Reporting configuration.");
        if (LogName.Equals("Security", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Warnings must not be written to Security.");
    }
}

/// <summary>Settings for authenticated SMTP; the password itself is never stored in this object/configuration.</summary>
public sealed class SmtpOptions
{
    // Gmail defaults: port 587 with mandatory STARTTLS; port 465 uses TLS from connection start.
    public string Host { get; set; } = "smtp.gmail.com";
    public int Port { get; set; } = 587;
    // Username is also the sender address; Recipient is the predefined alert destination.
    public string Username { get; set; } = "";
    public string Recipient { get; set; } = "";
    // Set-GmailCredential.ps1 writes machine-encrypted bytes here; GmailEmailSink decrypts them on Windows.
    public string PasswordFile { get; set; } = "%ProgramData%\\OSO\\gmail-password.bin";

    /// <summary>Check configuration shape only; actual credential decryption and SMTP access are separate checks.</summary>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Host) || Port is < 1 or > 65535 ||
            !MailboxAddress.TryParse(Username, out _) || !MailboxAddress.TryParse(Recipient, out _) ||
            string.IsNullOrWhiteSpace(PasswordFile))
            throw new ArgumentException("Configure a valid SMTP host, port, Gmail username, recipient and encrypted password file.");
    }
}
