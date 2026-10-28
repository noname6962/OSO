// Zamienia XML Windows na `LoginEvent`. Odczytuje konto, domenę, SID, IP, typ logowania i identyfikator sesji. Normalizuje nazwy i adresy, a brakujące pola zostawia jako brakujące. Zachowuje oryginalny XML.

using System.Globalization;
using System.Net;
using System.Xml;
using System.Xml.Linq;

namespace Oso.Core;

/// <summary>
/// Module 1 helper: translates Windows event XML into the shared LoginEvent model.
/// It uses XML field names rather than human-readable messages, which change with Windows language.
/// </summary>
public static class EventParser
{
    // Only these five event types are collected by the MVP.
    public static readonly int[] SupportedIds = [4624, 4625, 4634, 4647, 4672];

    /// <summary>Parse one record; malformed or unsupported records are rejected for the collector to log.</summary>
    public static LoginEvent Parse(string xml)
    {
        // Do not resolve external XML entities or allow unusually large input documents.
        using var text = new StringReader(xml);
        using var reader = XmlReader.Create(text, new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null,
            MaxCharactersInDocument = 4 * 1024 * 1024
        });
        var doc = XDocument.Load(reader);
        var root = doc.Root ?? throw new FormatException("Missing Event element.");
        // Windows XML uses a namespace, so element lookups must include that namespace.
        XNamespace ns = root.Name.Namespace;
        var system = root.Element(ns + "System") ?? throw new FormatException("Missing System element.");
        string Required(string name) => system.Element(ns + name)?.Value
            ?? throw new FormatException($"Missing {name}.");
        var id = int.Parse(Required("EventID"), CultureInfo.InvariantCulture);
        if (!SupportedIds.Contains(id)) throw new FormatException($"Unsupported event ID {id}.");
        // Preserve all named fields, even ones not directly used by the analyzer.
        var fields = root.Element(ns + "EventData")?.Elements(ns + "Data")
            .Where(d => d.Attribute("Name") != null)
            .ToDictionary(d => d.Attribute("Name")!.Value, d => d.Value, StringComparer.Ordinal)
            ?? new Dictionary<string, string>();
        // Windows often uses "-" for an unavailable field. Treat it as missing, not an identity.
        string? Get(string key) => fields.TryGetValue(key, out var value) &&
            !string.IsNullOrWhiteSpace(value) && value != "-" ? value : null;
        // 4624/4625/4634 describe the affected account with Target* fields.
        // 4647/4672 use Subject* fields for the account initiating the action.
        var prefix = id is 4647 or 4672 ? "Subject" : "Target";
        var name = Get(prefix + "UserName");
        var domain = Get(prefix + "DomainName");
        var sid = Get(prefix + "UserSid");
        // Windows account names are compared without case; retain the domain to distinguish namesakes.
        // S-1-0-0 is Windows' null SID and must not become a real account identity.
        var account = name is null ? (sid is null or "S-1-0-0" ? null : sid)
            : (domain is null ? name : $"{domain}\\{name}").ToUpperInvariant();
        var ipText = Get("IpAddress");
        string? ip = null;
        // Reject unspecified addresses and collapse IPv4-mapped IPv6 into ordinary IPv4,
        // so one source is not counted as two different IPs.
        if (IPAddress.TryParse(ipText, out var address) &&
            !address.Equals(IPAddress.Any) && !address.Equals(IPAddress.IPv6Any))
            ip = (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address).ToString();
        var logon = Get(prefix + "LogonId")?.ToLowerInvariant();
        // A zero logon ID does not identify a usable session for correlation.
        if (logon is "0x0" or "0") logon = null;
        var timestampText = system.Element(ns + "TimeCreated")?.Attribute("SystemTime")?.Value
            ?? throw new FormatException("Missing SystemTime.");
        // LogonType may be absent on privilege/logoff records; keep null instead of inventing a type.
        return new LoginEvent(id, long.Parse(Required("EventRecordID"), CultureInfo.InvariantCulture),
            DateTimeOffset.Parse(timestampText, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal),
            Required("Computer"), Required("Channel"), account, sid, ip,
            int.TryParse(Get("LogonType"), out var type) ? type : null,
            logon, fields, xml);
    }
}
