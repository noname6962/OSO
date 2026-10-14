using Oso.Core;
using Xunit;

namespace Oso.Tests;

public sealed class AnalyzerTests
{
    private static readonly DateTimeOffset Now = EventFactory.Now;

    [Fact]
    public void ThresholdIsInclusiveAndEverySubsequentFailureAlerts()
    {
        var analyzer = new LoginAnalyzer(new DetectionOptions());
        for (var i = 1; i < 5; i++) Assert.Null(analyzer.Process(EventFactory.Create(i), Now));
        var first = analyzer.Process(EventFactory.Create(5), Now)!;
        var next = analyzer.Process(EventFactory.Create(6), Now)!;
        Assert.Equal("RepeatedAccountFailures", Assert.Single(first.Matches).Rule);
        Assert.Equal(5, first.Matches[0].Failures);
        Assert.Equal(6, next.Matches[0].Failures);
        Assert.NotEqual(first.Id, next.Id);
        Assert.Equal(5, first.Evidence.Count);
    }

    [Theory]
    [InlineData(5, true)] [InlineData(5.001, false)]
    public void FiveMinuteWindowBoundary(double ageMinutes, bool expected)
    {
        var analyzer = new LoginAnalyzer(new DetectionOptions());
        for (var i = 1; i < 5; i++) analyzer.Process(EventFactory.Create(i, at: Now.AddMinutes(-ageMinutes)), Now);
        Assert.Equal(expected, analyzer.Process(EventFactory.Create(5), Now) != null);
    }

    [Fact]
    public void DetectsOneIpAcrossThreeAccounts()
    {
        var analyzer = new LoginAnalyzer(new DetectionOptions());
        for (var i = 1; i < 5; i++) analyzer.Process(EventFactory.Create(i, account: "user" + i % 3), Now);
        var alert = analyzer.Process(EventFactory.Create(5, account: "user2"), Now)!;
        var rule = Assert.Single(alert.Matches);
        Assert.Equal("OneIpMultipleAccounts", rule.Rule);
        Assert.Equal(3, rule.Accounts);
    }

    [Fact]
    public void TwoAccountsDoNotMeetSprayThreshold()
    {
        var analyzer = new LoginAnalyzer(new DetectionOptions());
        for (var i = 1; i <= 6; i++) Assert.Null(analyzer.Process(EventFactory.Create(i, account: "user" + i % 2), Now));
    }

    [Fact]
    public void DistributedFailuresListBothApplicableRulesInOneAlert()
    {
        var analyzer = new LoginAnalyzer(new DetectionOptions());
        for (var i = 1; i < 5; i++) analyzer.Process(EventFactory.Create(i, ip: "192.0.2." + (i % 3 + 1)), Now);
        var alert = analyzer.Process(EventFactory.Create(5, ip: "192.0.2.3"), Now)!;
        Assert.Equal(2, alert.Matches.Count);
        Assert.Contains(alert.Matches, m => m.Rule == "MultipleIpsOneAccount" && m.SourceIps == 3);
    }

    [Fact]
    public void AccountDetectionWorksWithoutSourceIp()
    {
        var analyzer = new LoginAnalyzer(new DetectionOptions());
        SecurityAlert? alert = null;
        for (var i = 1; i <= 5; i++) alert = analyzer.Process(EventFactory.Create(i, ip: null), Now);
        Assert.Equal("RepeatedAccountFailures", Assert.Single(alert!.Matches).Rule);
        Assert.Equal(0, alert.Matches[0].SourceIps);
    }

    [Fact]
    public void AccountDomainIsPartOfIdentity()
    {
        var analyzer = new LoginAnalyzer(new DetectionOptions());
        for (var i = 1; i <= 6; i++) Assert.Null(analyzer.Process(EventFactory.Create(i, domain: i % 2 == 0 ? "A" : "B"), Now));
    }

    [Fact]
    public void SuccessAfterFailuresAlertsButUnrelatedSuccessDoesNot()
    {
        var analyzer = new LoginAnalyzer(new DetectionOptions());
        for (var i = 1; i <= 5; i++) analyzer.Process(EventFactory.Create(i), Now);
        Assert.Null(analyzer.Process(EventFactory.Create(6, 4624, "bob", "192.0.2.7"), Now));
        var alert = analyzer.Process(EventFactory.Create(7, 4624), Now)!;
        Assert.Equal("SuccessAfter:RepeatedAccountFailures", Assert.Single(alert.Matches).Rule);
    }

    [Fact]
    public void SuccessFromSprayingIpMustBelongToTargetedAccount()
    {
        var analyzer = new LoginAnalyzer(new DetectionOptions());
        for (var i = 1; i <= 5; i++) analyzer.Process(EventFactory.Create(i, account: "user" + i % 3), Now);
        Assert.Null(analyzer.Process(EventFactory.Create(6, 4624, "unrelated"), Now));
        var alert = analyzer.Process(EventFactory.Create(7, 4624, "user1"), Now)!;
        Assert.Equal("SuccessAfter:OneIpMultipleAccounts", Assert.Single(alert.Matches).Rule);
    }

    [Fact]
    public void SuccessOutsideWindowDoesNotAlert()
    {
        var analyzer = new LoginAnalyzer(new DetectionOptions());
        for (var i = 1; i <= 5; i++) analyzer.Process(EventFactory.Create(i), Now);
        Assert.Null(analyzer.Process(EventFactory.Create(6, 4624, at: Now.AddMinutes(6)), Now.AddMinutes(6)));
    }

    [Fact]
    public void SupportingEvidenceIncludesLogoffsPrivilegesAndSameComputerSession()
    {
        var analyzer = new LoginAnalyzer(new DetectionOptions());
        analyzer.Process(EventFactory.Create(10, 4672, ip: null, at: Now.AddMinutes(-9), session: "0xabc"), Now);
        analyzer.Process(EventFactory.Create(11, 4634, account: null, ip: null, at: Now.AddMinutes(-8), session: "0xabc"), Now);
        analyzer.Process(EventFactory.Create(12, 4647, ip: null, at: Now.AddMinutes(-7)), Now);
        analyzer.Process(EventFactory.Create(13, 4634, account: null, ip: null, session: "0xabc", computer: "OTHER"), Now);
        analyzer.Process(EventFactory.Create(14, 4624, "unrelated", "192.0.2.8"), Now);
        SecurityAlert? alert = null;
        for (var i = 1; i <= 5; i++) alert = analyzer.Process(EventFactory.Create(i), Now);
        Assert.Contains(alert!.Evidence, e => e.RecordId == 10);
        Assert.Contains(alert.Evidence, e => e.RecordId == 11);
        Assert.Contains(alert.Evidence, e => e.RecordId == 12);
        Assert.DoesNotContain(alert.Evidence, e => e.RecordId is 13 or 14);
    }

    [Fact]
    public void PrunesDuringIdleAndRejectsExpiredOrFutureRecords()
    {
        var analyzer = new LoginAnalyzer(new DetectionOptions());
        analyzer.Process(EventFactory.Create(1), Now);
        analyzer.Prune(Now.AddMinutes(11));
        Assert.Equal(0, analyzer.RetainedCount);
        Assert.Null(analyzer.Process(EventFactory.Create(2, at: Now.AddMinutes(-11)), Now));
        Assert.Null(analyzer.Process(EventFactory.Create(3, at: Now.AddMinutes(2)), Now));
        Assert.Equal(0, analyzer.RetainedCount);
    }

    [Fact]
    public void StartupAndLiveOverlapIsDeduplicatedButNewEventsAreNotGrouped()
    {
        var analyzer = new LoginAnalyzer(new DetectionOptions());
        for (var i = 1; i <= 5; i++) analyzer.Process(EventFactory.Create(i), Now);
        Assert.Null(analyzer.Process(EventFactory.Create(5), Now));
        Assert.NotNull(analyzer.Process(EventFactory.Create(6), Now));
        Assert.Equal(6, analyzer.RetainedCount);
    }

    [Fact]
    public void RejectsInconsistentRetentionConfiguration() => Assert.Throws<ArgumentException>(() =>
        new LoginAnalyzer(new DetectionOptions { RetentionMinutes = 5 }));
}
