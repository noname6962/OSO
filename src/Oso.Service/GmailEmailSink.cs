using System.Security.Cryptography;
using System.Text;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using Oso.Core;

namespace Oso.Service;

public sealed class GmailEmailSink(SmtpOptions options) : IEmailSink
{
    public static void ValidateCredential(SmtpOptions options)
    {
        var encrypted = File.ReadAllBytes(Environment.ExpandEnvironmentVariables(options.PasswordFile));
        var decrypted = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.LocalMachine);
        try
        {
            if (decrypted.Length == 0) throw new InvalidDataException("Encrypted Gmail credential is empty.");
        }
        finally { CryptographicOperations.ZeroMemory(decrypted); }
    }

    public async Task SendAsync(SecurityAlert alert, CancellationToken cancellationToken)
    {
        var encrypted = await File.ReadAllBytesAsync(Environment.ExpandEnvironmentVariables(options.PasswordFile), cancellationToken);
        var decrypted = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.LocalMachine);
        try
        {
            var message = new MimeMessage();
            message.From.Add(MailboxAddress.Parse(options.Username));
            message.To.Add(MailboxAddress.Parse(options.Recipient));
            message.MessageId = $"oso.{alert.Id.ToLowerInvariant()}@{options.Host}";
            message.Subject = $"[OSO] Suspicious login activity on {alert.Trigger.Computer}";
            var body = new BodyBuilder { TextBody = AlertFormatter.Summary(alert) };
            body.Attachments.Add($"events-{alert.Id}.xml", Encoding.UTF8.GetBytes(AlertFormatter.EvidenceXml(alert)), new ContentType("application", "xml"));
            message.Body = body.ToMessageBody();
            using var client = new SmtpClient { Timeout = 30000 };
            await client.ConnectAsync(options.Host, options.Port,
                options.Port == 465 ? SecureSocketOptions.SslOnConnect : SecureSocketOptions.StartTls, cancellationToken);
            await client.AuthenticateAsync(options.Username, Encoding.UTF8.GetString(decrypted), cancellationToken);
            await client.SendAsync(message, cancellationToken);
            await client.DisconnectAsync(true, cancellationToken);
        }
        finally { CryptographicOperations.ZeroMemory(decrypted); }
    }
}
