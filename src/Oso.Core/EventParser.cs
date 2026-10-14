using System.Globalization;
using System.Net;
using System.Xml;
using System.Xml.Linq;

namespace Oso.Core;

public static class EventParser
{
    public static readonly int[] SupportedIds = [4624, 4625, 4634, 4647, 4672];

    public static LoginEvent Parse(string xml)
    {
        using var text = new StringReader(xml);
        using var reader = XmlReader.Create(text, new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null,
            MaxCharactersInDocument = 4 * 1024 * 1024
        });
        var doc = XDocument.Load(reader);
        var root = doc.Root ?? throw new FormatException("Missing Event element.");
        XNamespace ns = root.Name.Namespace;
        var system = root.Element(ns + "System") ?? throw new FormatException("Missing System element.");
        string Required(string name) => system.Element(ns + name)?.Value
            ?? throw new FormatException($"Missing {name}.");
        var id = int.Parse(Required("EventID"), CultureInfo.InvariantCulture);
        if (!SupportedIds.Contains(id)) throw new FormatException($"Unsupported event ID {id}.");
        var fields = root.Element(ns + "EventData")?.Elements(ns + "Data")
            .Where(d => d.Attribute("Name") != null)
            .ToDictionary(d => d.Attribute("Name")!.Value, d => d.Value, StringComparer.Ordinal)
            ?? new Dictionary<string, string>();
        string? Get(string key) => fields.TryGetValue(key, out var value) &&
            !string.IsNullOrWhiteSpace(value) && value != "-" ? value : null;
        // Logoff/user-initiated logoff and privilege events use different account fields.
        var prefix = id is 4647 or 4672 ? "Subject" : "Target";
        var name = Get(prefix + "UserName");
        var domain = Get(prefix + "DomainName");
        var sid = Get(prefix + "UserSid");
        var account = name is null ? (sid is null or "S-1-0-0" ? null : sid)
            : (domain is null ? name : $"{domain}\\{name}").ToUpperInvariant();
        var ipText = Get("IpAddress");
        string? ip = null;
        if (IPAddress.TryParse(ipText, out var address) &&
            !address.Equals(IPAddress.Any) && !address.Equals(IPAddress.IPv6Any))
            ip = (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address).ToString();
        var logon = Get(prefix + "LogonId")?.ToLowerInvariant();
        if (logon is "0x0" or "0") logon = null;
        var timestampText = system.Element(ns + "TimeCreated")?.Attribute("SystemTime")?.Value
            ?? throw new FormatException("Missing SystemTime.");
        return new LoginEvent(id, long.Parse(Required("EventRecordID"), CultureInfo.InvariantCulture),
            DateTimeOffset.Parse(timestampText, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal),
            Required("Computer"), Required("Channel"), account, sid, ip,
            int.TryParse(Get("LogonType"), out var type) ? type : null,
            logon, fields, xml);
    }
}
