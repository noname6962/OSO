using System.Xml.Linq;
using Oso.Core;

namespace Oso.Tests;

internal static class EventFactory
{
    public static readonly DateTimeOffset Now = new(2026, 10, 14, 12, 0, 0, TimeSpan.Zero);

    public static LoginEvent Create(long recordId, int id = 4625, string? account = "alice",
        string? ip = "192.0.2.1", DateTimeOffset? at = null, string? session = null,
        string domain = "VM", string computer = "VM")
    {
        XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
        var prefix = id is 4647 or 4672 ? "Subject" : "Target";
        var data = new Dictionary<string, string>
        {
            [prefix + "UserName"] = account ?? "-",
            [prefix + "DomainName"] = domain,
            [prefix + "UserSid"] = "S-1-0-0",
            ["IpAddress"] = ip ?? "-",
            ["LogonType"] = "3",
            [prefix + "LogonId"] = session ?? "0x0",
            ["Status"] = "0xC000006D"
        };
        var xml = new XElement(ns + "Event",
            new XElement(ns + "System", new XElement(ns + "EventID", id),
                new XElement(ns + "EventRecordID", recordId),
                new XElement(ns + "TimeCreated", new XAttribute("SystemTime", (at ?? Now).ToString("O"))),
                new XElement(ns + "Computer", computer), new XElement(ns + "Channel", "Security")),
            new XElement(ns + "EventData", data.Select(p => new XElement(ns + "Data", new XAttribute("Name", p.Key), p.Value))));
        return EventParser.Parse(xml.ToString());
    }

    public static SecurityAlert Alert(long recordId = 5)
    {
        var analyzer = new LoginAnalyzer(new DetectionOptions());
        SecurityAlert? alert = null;
        for (var i = 1; i <= 5; i++) alert = analyzer.Process(Create(recordId - 5 + i), Now);
        return alert!;
    }
}
