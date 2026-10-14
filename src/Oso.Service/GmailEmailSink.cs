using System.Security.Cryptography;
using System.Text;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using Oso.Core;

namespace Oso.Service;

/// <summary>Module 3 email adapter: sends readable alerts and XML evidence over authenticated, encrypted SMTP.</summary>
public sealed class GmailEmailSink(SmtpOptions options) : IEmailSink
{
    /// <summary>Check that Windows can decrypt the saved credential; this does not contact Gmail.</summary>
    public static void ValidateCredential(SmtpOptions options)
    {
        var encrypted = File.ReadAllBytes(Environment.ExpandEnvironmentVariables(options.PasswordFile));
        // Machine-bound DPAPI matches Set-GmailCredential.ps1. File ACLs restrict who can read it.
        var decrypted = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.LocalMachine);
        try
        {
            if (decrypted.Length == 0) throw new InvalidDataException("Encrypted Gmail credential is empty.");
        }
        finally { CryptographicOperations.ZeroMemory(decrypted); }
    }

    /// <summary>Send one alert; exceptions propagate to DurableReporter, which schedules a retry.</summary>
    public async Task SendAsync(SecurityAlert alert, CancellationToken cancellationToken)
    {
        // Read on each attempt so replacing the credential file also fixes already pending deliveries.
        var encrypted = await File.ReadAllBytesAsync(Environment.ExpandEnvironmentVariables(options.PasswordFile), cancellationToken);
        var decrypted = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.LocalMachine);
        try
        {
            var message = new MimeMessage();
            message.From.Add(MailboxAddress.Parse(options.Username));
            message.To.Add(MailboxAddress.Parse(options.Recipient));
            // Stable across retries for traceability; this does not guarantee mailbox deduplication.
            message.MessageId = $"oso.{alert.Id.ToLowerInvariant()}@{options.Host}";
            message.Subject = $"[OSO] Suspicious login activity on {alert.Trigger.Computer}";
            // Keep the body readable and attach full original evidence rather than flattening its fields.
            var body = new BodyBuilder { TextBody = AlertFormatter.Summary(alert) };
            body.Attachments.Add($"events-{alert.Id}.xml", Encoding.UTF8.GetBytes(AlertFormatter.EvidenceXml(alert)), new ContentType("application", "xml"));
            message.Body = body.ToMessageBody();
            using var client = new SmtpClient { Timeout = 30000 };
            // Port 465 encrypts from connection start; other ports require STARTTLS before authentication.
            // MailKit's normal server certificate verification remains enabled.
            await client.ConnectAsync(options.Host, options.Port,
                options.Port == 465 ? SecureSocketOptions.SslOnConnect : SecureSocketOptions.StartTls, cancellationToken);
            await client.AuthenticateAsync(options.Username, Encoding.UTF8.GetString(decrypted), cancellationToken);
            await client.SendAsync(message, cancellationToken);
            await client.DisconnectAsync(true, cancellationToken);
        }
        // Clear the decrypted byte buffer even when SMTP fails. The authentication API also
        // requires a managed string, which cannot be explicitly zeroed by this call.
        finally { CryptographicOperations.ZeroMemory(decrypted); }
    }
}
