// Wspólne struktury danych: `LoginEvent` to odczytane zdarzenie, `RuleMatch` to spełniona reguła z licznikami, a `SecurityAlert` to alert z dowodami. Zawiera też `DetectionOptions`, czyli progi i okna czasowe. Wylicza stały identyfikator alertu na podstawie zdarzenia.

using System.Security.Cryptography;
using System.Text;

namespace Oso.Core;

/// <summary>
/// The shared event format passed from Module 1 (collector) to Module 2 (analyzer).
/// Normalized fields support comparisons; Fields and Xml preserve the original evidence.
/// </summary>
/// <param name="EventId">Windows event type: 4624 success, 4625 failure, 4634/4647 logoff, or 4672 special privileges.</param>
/// <param name="RecordId">Record number assigned by the Windows Event Log.</param>
/// <param name="Timestamp">When Windows recorded the event, expressed in UTC.</param>
/// <param name="Computer">Machine that generated the event; also used to distinguish sessions.</param>
/// <param name="Channel">Windows log containing the record, normally Security.</param>
/// <param name="Account">Normalized domain/account name, or SID fallback when the name is unavailable.</param>
/// <param name="Sid">Original Windows security identifier, if available.</param>
/// <param name="SourceIp">Normalized IPv4/IPv6 address, or null when Windows did not provide a usable address.</param>
/// <param name="LogonType">Windows logon category, for example 2 = interactive, 3 = network, 10 = remote interactive.</param>
/// <param name="LogonId">Windows session identifier used to connect login, privilege and logoff records.</param>
/// <param name="Fields">Original named EventData values, including failure status and workstation information.</param>
/// <param name="Xml">Original event XML included in warnings and the email attachment.</param>
public sealed record LoginEvent(
    int EventId, long RecordId, DateTimeOffset Timestamp, string Computer,
    string Channel, string? Account, string? Sid, string? SourceIp,
    int? LogonType, string? LogonId, IReadOnlyDictionary<string, string> Fields,
    string Xml)
{
    // Record numbers can be reused after a log is cleared. Including the timestamp,
    // computer and channel distinguishes those records from previously processed ones.
    public string Identity => $"{Computer}|{Channel}|{RecordId}|{Timestamp:O}";
}

/// <summary>A detection rule that matched, together with the failure/account/IP counts explaining it.</summary>
public sealed record RuleMatch(string Rule, int Failures, int Accounts, int SourceIps);

/// <summary>
/// Module 2's output for Module 3: one triggering event, all matching rules,
/// and the related events available when the alert was created.
/// </summary>
public sealed record SecurityAlert(
    string Id, DateTimeOffset DetectedAt, LoginEvent Trigger,
    IReadOnlyList<RuleMatch> Matches, IReadOnlyList<LoginEvent> Evidence)
{
    // The same Windows record produces the same ID after a service restart.
    // The outbox uses this ID to recognize replayed alerts; new records get new IDs.
    public static string IdFor(LoginEvent trigger) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(trigger.Identity)));
}

/// <summary>Settings loaded from the Detection section of appsettings.json.</summary>
public sealed class DetectionOptions
{
    // Rules count failed logins inside this period, ending at the triggering event.
    public int WindowMinutes { get; set; } = 5;
    // Keep a longer history for supporting evidence; expiry only affects program memory.
    public int RetentionMinutes { get; set; } = 10;
    // On service startup, reread this much history before consuming buffered live events.
    public int StartupLookbackMinutes { get; set; } = 10;
    // Minimum number of 4625 records required by each failure-based rule.
    public int FailureThreshold { get; set; } = 5;
    // One-IP/multiple-account rule: at least this many different accounts.
    public int DistinctAccountThreshold { get; set; } = 3;
    // Multiple-IP/one-account rule: at least this many different source addresses.
    public int DistinctIpThreshold { get; set; } = 3;

    /// <summary>Reject settings that would make rules or evidence retention inconsistent.</summary>
    public void Validate()
    {
        if (WindowMinutes <= 0 || FailureThreshold <= 0 ||
            DistinctAccountThreshold <= 0 || DistinctIpThreshold <= 0 ||
            RetentionMinutes < 2L * WindowMinutes ||
            StartupLookbackMinutes < WindowMinutes || StartupLookbackMinutes > RetentionMinutes)
            throw new ArgumentException("Detection thresholds must be positive; retention must be at least twice the window and contain the startup lookback.");
    }
}
