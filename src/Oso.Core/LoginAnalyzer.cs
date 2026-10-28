// Sprawdza powtarzające się nieudane logowania, jeden IP atakujący wiele kont, wiele IP atakujących jedno konto i sukces po podejrzanych niepowodzeniach. Trzyma ostatnie zdarzenia w pamięci, usuwa stare i dołącza powiązane rekordy do alertu. Pomija ponowne odczytanie tego samego zdarzenia.

namespace Oso.Core;

/// <summary>
/// Module 2: keeps recent events, checks login rules, and assembles supporting evidence.
/// MonitorWorker calls it from one consumer; this class is not designed for concurrent callers.
/// </summary>
public sealed class LoginAnalyzer
{
    private readonly DetectionOptions options;
    // The key also prevents a record seen during both startup replay and live watching being counted twice.
    private readonly Dictionary<string, LoginEvent> history = new(StringComparer.Ordinal);

    public LoginAnalyzer(DetectionOptions options)
    {
        options.Validate();
        this.options = options;
    }

    /// <summary>Number of event records currently retained in memory.</summary>
    public int RetainedCount => history.Count;

    /// <summary>Discard expired in-memory evidence. This never deletes Windows Event Log records.</summary>
    public void Prune(DateTimeOffset now)
    {
        var cutoff = now.AddMinutes(-options.RetentionMinutes);
        foreach (var key in history.Where(p => p.Value.Timestamp < cutoff).Select(p => p.Key).ToArray())
            history.Remove(key);
    }

    /// <summary>
    /// Store and evaluate one event. Return null for a duplicate, irrelevant record or unmatched rule.
    /// 'now' is processing time; item.Timestamp is event time, which can be older during startup replay.
    /// </summary>
    public SecurityAlert? Process(LoginEvent item, DateTimeOffset now)
    {
        Prune(now);
        // Reject expired records and records more than one minute in the future.
        // Store the current event before evaluating, so the fifth failure meets a threshold of five.
        if (item.Timestamp < now.AddMinutes(-options.RetentionMinutes) || item.Timestamp > now.AddMinutes(1) ||
            !history.TryAdd(item.Identity, item)) return null;
        // Logoff and special-privilege events remain available as evidence but do not trigger rules.
        if (item.EventId is not (4624 or 4625)) return null;

        // Count only failed logins in the inclusive window preceding this event.
        // Using event time allows startup replay to analyze the original sequence of activity.
        var cutoff = item.Timestamp.AddMinutes(-options.WindowMinutes);
        var failures = history.Values.Where(e => e.EventId == 4625 &&
            e.Timestamp >= cutoff && e.Timestamp <= item.Timestamp).ToArray();
        var matches = new List<RuleMatch>();
        // Matching failures expand these sets to include all accounts/IPs involved in the pattern.
        var relatedAccounts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var relatedIps = new HashSet<string>(StringComparer.Ordinal);
        if (item.Account is not null) relatedAccounts.Add(item.Account);
        if (item.SourceIp is not null) relatedIps.Add(item.SourceIp);

        // A success does not add a failure. It alerts when preceding failures still meet a rule,
        // using a SuccessAfter: prefix to explain why a successful login is suspicious.
        void Match(string rule, LoginEvent[] selected)
        {
            matches.Add(new RuleMatch(item.EventId == 4624 ? "SuccessAfter:" + rule : rule,
                selected.Length, selected.Where(e => e.Account != null).Select(e => e.Account).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
                selected.Where(e => e.SourceIp != null).Select(e => e.SourceIp).Distinct().Count()));
            foreach (var e in selected)
            {
                if (e.Account != null) relatedAccounts.Add(e.Account);
                if (e.SourceIp != null) relatedIps.Add(e.SourceIp);
            }
        }

        // Rule 1: repeated failures against one account, even if source IP is unavailable.
        var accountFailures = failures.Where(e => item.Account is not null &&
            string.Equals(e.Account, item.Account, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (accountFailures.Length >= options.FailureThreshold)
            Match("RepeatedAccountFailures", accountFailures);
        // Rule 2: one IP tries multiple accounts. For a successful login, require that
        // its account was actually targeted; another account sharing the IP is not enough.
        var ipFailures = failures.Where(e => item.SourceIp is not null && e.SourceIp == item.SourceIp).ToArray();
        if (ipFailures.Length >= options.FailureThreshold &&
            ipFailures.Where(e => e.Account != null).Select(e => e.Account).Distinct(StringComparer.OrdinalIgnoreCase).Count() >= options.DistinctAccountThreshold &&
            (item.EventId == 4625 || (item.Account is not null && ipFailures.Any(e => string.Equals(e.Account, item.Account, StringComparison.OrdinalIgnoreCase)))))
            Match("OneIpMultipleAccounts", ipFailures);
        // Rule 3: multiple IPs fail against one account. A single event can match
        // this and Rule 1; both explanations belong to the same alert.
        if (accountFailures.Length >= options.FailureThreshold &&
            accountFailures.Where(e => e.SourceIp != null).Select(e => e.SourceIp).Distinct().Count() >= options.DistinctIpThreshold)
            Match("MultipleIpsOneAccount", accountFailures);
        if (matches.Count == 0) return null;

        // Evidence uses the longer retention window, including successes, logoffs and privileges.
        // Include only records already known at the trigger's time; future events are not added later.
        var candidates = history.Values.Where(e => e.Timestamp <= item.Timestamp &&
            e.Timestamp >= item.Timestamp.AddMinutes(-options.RetentionMinutes)).ToArray();
        bool Related(LoginEvent e) => e.Account is not null && relatedAccounts.Contains(e.Account) ||
            e.SourceIp is not null && relatedIps.Contains(e.SourceIp);
        // Account/IP events seed session correlation, linking records without an IP/account.
        // Logon IDs are scoped to a computer; equal IDs on another computer are unrelated.
        var sessions = candidates.Where(Related).Where(e => e.LogonId != null)
            .Select(e => (e.Computer.ToUpperInvariant(), e.LogonId)).ToHashSet();
        var evidence = candidates.Where(e => e.Identity == item.Identity || Related(e) ||
            e.LogonId is not null && sessions.Contains((e.Computer.ToUpperInvariant(), e.LogonId)))
            .OrderBy(e => e.Timestamp).ThenBy(e => e.RecordId).ToArray();
        // No cooldown/grouping: every new qualifying event returns its own alert.
        return new SecurityAlert(SecurityAlert.IdFor(item), now, item, matches, evidence);
    }
}
