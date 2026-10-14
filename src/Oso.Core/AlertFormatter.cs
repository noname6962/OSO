using System.Text;

namespace Oso.Core;

/// <summary>Module 3 formatting shared by Windows warnings and Gmail messages.</summary>
public static class AlertFormatter
{
    /// <summary>A readable explanation of the trigger, matching rules and supporting-event count.</summary>
    public static string Summary(SecurityAlert alert) =>
        $"OSO suspicious login activity\nAlert: {alert.Id}\nDetected (UTC): {alert.DetectedAt:O}\n" +
        $"Computer: {alert.Trigger.Computer}\nAccount: {alert.Trigger.Account ?? "unavailable"}\n" +
        $"Source IP: {alert.Trigger.SourceIp ?? "unavailable"}\n" +
        $"Trigger: {alert.Trigger.EventId}, record {alert.Trigger.RecordId}, logon type {alert.Trigger.LogonType?.ToString() ?? "unavailable"}\n" +
        string.Join("\n", alert.Matches.Select(m => $"Rule: {m.Rule}; failures={m.Failures}; accounts={m.Accounts}; IPs={m.SourceIps}")) +
        $"\nSupporting events: {alert.Evidence.Count}\nThis is a rule-based suspicion, not confirmation of malicious intent.\n";

    /// <summary>Wrap the original event XML records in one document for the email attachment.</summary>
    public static string EvidenceXml(SecurityAlert alert) =>
        "<Events>\n" + string.Join("\n", alert.Evidence.Select(e => e.Xml)) + "\n</Events>";

    /// <summary>Split a warning into numbered entries so large evidence fits Windows Event Log messages.</summary>
    public static IReadOnlyList<string> WarningEntries(SecurityAlert alert, int maxChars = 14000)
    {
        if (maxChars < 512) throw new ArgumentOutOfRangeException(nameof(maxChars));
        var content = Summary(alert) + "\n" + EvidenceXml(alert);
        var pieces = new List<string>();
        // Reserve space for the alert ID and part number. The default also leaves room
        // below Event Log message-size limits when characters are encoded as UTF-16.
        var capacity = maxChars - 160;
        for (var offset = 0; offset < content.Length;)
        {
            var length = Math.Min(capacity, content.Length - offset);
            // Avoid splitting a Unicode character represented by a pair of UTF-16 code units.
            if (offset + length < content.Length && char.IsHighSurrogate(content[offset + length - 1])) length--;
            pieces.Add(content.Substring(offset, length));
            offset += length;
        }
        // Each part carries the same ID so the complete warning can be reconstructed.
        return pieces.Select((part, i) => $"Alert {alert.Id}; part {i + 1}/{pieces.Count}\n{part}").ToArray();
    }
}
