using System.Text;

namespace Oso.Core;

public static class AlertFormatter
{
    public static string Summary(SecurityAlert alert) =>
        $"OSO suspicious login activity\nAlert: {alert.Id}\nDetected (UTC): {alert.DetectedAt:O}\n" +
        $"Computer: {alert.Trigger.Computer}\nAccount: {alert.Trigger.Account ?? "unavailable"}\n" +
        $"Source IP: {alert.Trigger.SourceIp ?? "unavailable"}\n" +
        $"Trigger: {alert.Trigger.EventId}, record {alert.Trigger.RecordId}, logon type {alert.Trigger.LogonType?.ToString() ?? "unavailable"}\n" +
        string.Join("\n", alert.Matches.Select(m => $"Rule: {m.Rule}; failures={m.Failures}; accounts={m.Accounts}; IPs={m.SourceIps}")) +
        $"\nSupporting events: {alert.Evidence.Count}\nThis is a rule-based suspicion, not confirmation of malicious intent.\n";

    public static string EvidenceXml(SecurityAlert alert) =>
        "<Events>\n" + string.Join("\n", alert.Evidence.Select(e => e.Xml)) + "\n</Events>";

    public static IReadOnlyList<string> WarningEntries(SecurityAlert alert, int maxChars = 14000)
    {
        if (maxChars < 512) throw new ArgumentOutOfRangeException(nameof(maxChars));
        var content = Summary(alert) + "\n" + EvidenceXml(alert);
        var pieces = new List<string>();
        var capacity = maxChars - 160;
        for (var offset = 0; offset < content.Length;)
        {
            var length = Math.Min(capacity, content.Length - offset);
            if (offset + length < content.Length && char.IsHighSurrogate(content[offset + length - 1])) length--;
            pieces.Add(content.Substring(offset, length));
            offset += length;
        }
        return pieces.Select((part, i) => $"Alert {alert.Id}; part {i + 1}/{pieces.Count}\n{part}").ToArray();
    }
}
