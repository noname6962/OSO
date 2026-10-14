using Oso.Core;
using Xunit;

namespace Oso.Tests;

public sealed class ReporterTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), "oso-tests-" + Guid.NewGuid());
    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = EventFactory.Now;
        public override DateTimeOffset GetUtcNow() => Now;
    }
    private sealed class Warnings : IWarningSink
    {
        public List<string> Entries { get; } = [];
        public bool Fail { get; set; }
        public Task WriteAsync(string entry, CancellationToken ct)
        {
            if (Fail) throw new IOException("Simulated Event Log failure");
            Entries.Add(entry);
            return Task.CompletedTask;
        }
    }
    private sealed class Email(Warnings warnings) : IEmailSink
    {
        public List<SecurityAlert> Sent { get; } = [];
        public bool Fail { get; set; }
        public Task SendAsync(SecurityAlert alert, CancellationToken ct)
        {
            Assert.NotEmpty(warnings.Entries);
            if (Fail) throw new IOException("Simulated SMTP failure");
            Sent.Add(alert);
            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task PersistsEvidenceThenWritesWarningBeforeEmailAndDropsDeliveredPayload()
    {
        var store = new FileOutbox(directory);
        var warnings = new Warnings();
        var email = new Email(warnings);
        var reporter = new DurableReporter(store, warnings, email, new Clock());
        var alert = EventFactory.Alert();
        Assert.True(await reporter.AcceptAsync(alert));
        var restored = Assert.Single(await new FileOutbox(directory).ReadAsync()).Alert!;
        Assert.Equal(alert.Trigger.Fields["Status"], restored.Trigger.Fields["Status"]);
        Assert.Equal(5, restored.Evidence.Count);
        await reporter.ProcessPendingAsync();
        Assert.Single(email.Sent);
        var completed = Assert.Single(await store.ReadAsync());
        Assert.NotNull(completed.CompletedAt);
        Assert.Null(completed.Alert);
    }

    [Fact]
    public async Task FailedEmailIsRetriedAfterRestartWithoutRewritingWarnings()
    {
        var store = new FileOutbox(directory);
        var warnings = new Warnings();
        var email = new Email(warnings) { Fail = true };
        var clock = new Clock();
        var reporter = new DurableReporter(store, warnings, email, clock);
        await reporter.AcceptAsync(EventFactory.Alert());
        await reporter.ProcessPendingAsync();
        var pending = Assert.Single(await store.ReadAsync());
        Assert.NotNull(pending.Alert);
        Assert.Equal(1, pending.Attempts);
        await reporter.ProcessPendingAsync();
        Assert.Empty(email.Sent);
        email.Fail = false;
        clock.Now = clock.Now.AddSeconds(16);
        var restarted = new DurableReporter(new FileOutbox(directory), warnings, email, clock);
        await restarted.ProcessPendingAsync();
        Assert.Single(warnings.Entries);
        Assert.Single(email.Sent);
    }

    [Fact]
    public async Task RestartReplayDoesNotDuplicateDeliveredAlertButNewTriggerDoes()
    {
        var store = new FileOutbox(directory);
        var warnings = new Warnings();
        var email = new Email(warnings);
        var reporter = new DurableReporter(store, warnings, email, new Clock());
        await reporter.AcceptAsync(EventFactory.Alert());
        await reporter.ProcessPendingAsync();
        var restart = new DurableReporter(new FileOutbox(directory), warnings, email, new Clock());
        Assert.False(await restart.AcceptAsync(EventFactory.Alert()));
        Assert.True(await restart.AcceptAsync(EventFactory.Alert(6)));
        await restart.ProcessPendingAsync();
        Assert.Equal(2, email.Sent.Count);
    }

    [Fact]
    public async Task WarningFailureKeepsEvidenceAndPreventsPrematureEmail()
    {
        var store = new FileOutbox(directory);
        var warnings = new Warnings { Fail = true };
        var email = new Email(warnings);
        var reporter = new DurableReporter(store, warnings, email, new Clock());
        await reporter.AcceptAsync(EventFactory.Alert());
        await reporter.ProcessPendingAsync();
        Assert.Empty(email.Sent);
        Assert.NotNull(Assert.Single(await store.ReadAsync()).Alert);
    }

    [Fact]
    public async Task CleanupRemovesOnlyOldDeliveredMetadataNotPendingEvidence()
    {
        var store = new FileOutbox(directory);
        var warnings = new Warnings();
        var email = new Email(warnings);
        var reporter = new DurableReporter(store, warnings, email, new Clock());
        await reporter.AcceptAsync(EventFactory.Alert());
        await reporter.ProcessPendingAsync();
        await reporter.AcceptAsync(EventFactory.Alert(6));
        await store.PruneCompletedAsync(EventFactory.Now.AddHours(25));
        var pending = Assert.Single(await store.ReadAsync());
        Assert.NotNull(pending.Alert);
        Assert.Null(pending.CompletedAt);
    }

    [Fact]
    public void LargeWarningEvidenceIsSplitLosslesslyWithAlertId()
    {
        var alert = EventFactory.Alert();
        var parts = AlertFormatter.WarningEntries(alert, 600);
        Assert.True(parts.Count > 1);
        Assert.All(parts, p => { Assert.True(p.Length <= 600); Assert.Contains(alert.Id, p); });
        var restored = string.Concat(parts.Select(p => p[(p.IndexOf('\n') + 1)..]));
        Assert.Equal(AlertFormatter.Summary(alert) + "\n" + AlertFormatter.EvidenceXml(alert), restored);
    }

    [Fact]
    public async Task MalformedOutboxFailsVisiblyRatherThanDiscardingEvidence()
    {
        var store = new FileOutbox(directory);
        await File.WriteAllTextAsync(Path.Combine(directory, new string('A', 64) + ".json"), "broken");
        await Assert.ThrowsAsync<System.Text.Json.JsonException>(() => store.ReadAsync());
    }

    public void Dispose() { if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true); }
}
