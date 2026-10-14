using Oso.Core;
using Xunit;

namespace Oso.Tests;

public sealed class ParserTests
{
    [Theory]
    [InlineData(4624)] [InlineData(4625)] [InlineData(4634)] [InlineData(4647)] [InlineData(4672)]
    public void ParsesAllSupportedEventsWithCorrectAccountFields(int id)
    {
        var item = EventFactory.Create(17, id, session: "0xAbC");
        Assert.Equal(id, item.EventId);
        Assert.Equal("VM\\ALICE", item.Account);
        Assert.Equal(3, item.LogonType);
        Assert.Equal("0xabc", item.LogonId);
        Assert.Equal("0xC000006D", item.Fields["Status"]);
        Assert.Contains("EventData", item.Xml);
    }

    [Theory]
    [InlineData("::ffff:192.0.2.1", "192.0.2.1")]
    [InlineData("2001:0db8::1", "2001:db8::1")]
    [InlineData("-", null)] [InlineData("not-an-ip", null)]
    [InlineData("0.0.0.0", null)] [InlineData("::", null)]
    public void NormalizesOrRejectsAddresses(string input, string? expected) =>
        Assert.Equal(expected, EventFactory.Create(1, ip: input).SourceIp);

    [Fact]
    public void MissingIdentityDoesNotCreateAnArtificialAccount()
    {
        var item = EventFactory.Create(1, account: null, ip: null);
        Assert.Null(item.Account);
        Assert.Null(item.SourceIp);
        Assert.Null(item.LogonId);
    }

    [Fact]
    public void RejectsUnsupportedEvent() => Assert.Throws<FormatException>(() => EventFactory.Create(1, 9999));

    [Fact]
    public void RejectsExternalEntities() => Assert.Throws<System.Xml.XmlException>(() =>
        EventParser.Parse("<!DOCTYPE Event [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><Event>&x;</Event>"));
}
