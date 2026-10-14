namespace Oso.Core;

// Used by one consumer. All age calculations use UTC event timestamps.
public sealed class LoginAnalyzer
{
    private readonly DetectionOptions options;
    private readonly Dictionary<string, LoginEvent> history = new(StringComparer.Ordinal);

    public LoginAnalyzer(DetectionOptions options)
    {
        options.Validate();
        this.options = options;
    }

    public int RetainedCount => history.Count;

    public void Prune(DateTimeOffset now)
    {
        var cutoff = now.AddMinutes(-options.RetentionMinutes);
        foreach (var key in history.Where(p => p.Value.Timestamp < cutoff).Select(p => p.Key).ToArray())
            history.Remove(key);
    }

    public SecurityAlert? Process(LoginEvent item, DateTimeOffset now)
    {
        Prune(now);
        if (item.Timestamp < now.AddMinutes(-options.RetentionMinutes) || item.Timestamp > now.AddMinutes(1) ||
            !history.TryAdd(item.Identity, item)) return null;
        if (item.EventId is not (4624 or 4625)) return null;

        var cutoff = item.Timestamp.AddMinutes(-options.WindowMinutes);
        var failures = history.Values.Where(e => e.EventId == 4625 &&
            e.Timestamp >= cutoff && e.Timestamp <= item.Timestamp).ToArray();
        var matches = new List<RuleMatch>();
        var relatedAccounts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var relatedIps = new HashSet<string>(StringComparer.Ordinal);
        if (item.Account is not null) relatedAccounts.Add(item.Account);
        if (item.SourceIp is not null) relatedIps.Add(item.SourceIp);

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

        var accountFailures = failures.Where(e => item.Account is not null &&
            string.Equals(e.Account, item.Account, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (accountFailures.Length >= options.FailureThreshold)
            Match("RepeatedAccountFailures", accountFailures);
        var ipFailures = failures.Where(e => item.SourceIp is not null && e.SourceIp == item.SourceIp).ToArray();
        if (ipFailures.Length >= options.FailureThreshold &&
            ipFailures.Where(e => e.Account != null).Select(e => e.Account).Distinct(StringComparer.OrdinalIgnoreCase).Count() >= options.DistinctAccountThreshold &&
            (item.EventId == 4625 || (item.Account is not null && ipFailures.Any(e => string.Equals(e.Account, item.Account, StringComparison.OrdinalIgnoreCase)))))
            Match("OneIpMultipleAccounts", ipFailures);
        if (accountFailures.Length >= options.FailureThreshold &&
            accountFailures.Where(e => e.SourceIp != null).Select(e => e.SourceIp).Distinct().Count() >= options.DistinctIpThreshold)
            Match("MultipleIpsOneAccount", accountFailures);
        if (matches.Count == 0) return null;

        var candidates = history.Values.Where(e => e.Timestamp <= item.Timestamp &&
            e.Timestamp >= item.Timestamp.AddMinutes(-options.RetentionMinutes)).ToArray();
        bool Related(LoginEvent e) => e.Account is not null && relatedAccounts.Contains(e.Account) ||
            e.SourceIp is not null && relatedIps.Contains(e.SourceIp);
        // Account/IP events seed session correlation, linking records without an IP/account.
        var sessions = candidates.Where(Related).Where(e => e.LogonId != null)
            .Select(e => (e.Computer.ToUpperInvariant(), e.LogonId)).ToHashSet();
        var evidence = candidates.Where(e => e.Identity == item.Identity || Related(e) ||
            e.LogonId is not null && sessions.Contains((e.Computer.ToUpperInvariant(), e.LogonId)))
            .OrderBy(e => e.Timestamp).ThenBy(e => e.RecordId).ToArray();
        return new SecurityAlert(SecurityAlert.IdFor(item), now, item, matches, evidence);
    }
}
