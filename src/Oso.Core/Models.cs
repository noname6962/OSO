using System.Security.Cryptography;
using System.Text;

namespace Oso.Core;

public sealed record LoginEvent(
    int EventId, long RecordId, DateTimeOffset Timestamp, string Computer,
    string Channel, string? Account, string? Sid, string? SourceIp,
    int? LogonType, string? LogonId, IReadOnlyDictionary<string, string> Fields,
    string Xml)
{
    public string Identity => $"{Computer}|{Channel}|{RecordId}|{Timestamp:O}";
}

public sealed record RuleMatch(string Rule, int Failures, int Accounts, int SourceIps);

public sealed record SecurityAlert(
    string Id, DateTimeOffset DetectedAt, LoginEvent Trigger,
    IReadOnlyList<RuleMatch> Matches, IReadOnlyList<LoginEvent> Evidence)
{
    public static string IdFor(LoginEvent trigger) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(trigger.Identity)));
}

public sealed class DetectionOptions
{
    public int WindowMinutes { get; set; } = 5;
    public int RetentionMinutes { get; set; } = 10;
    public int StartupLookbackMinutes { get; set; } = 10;
    public int FailureThreshold { get; set; } = 5;
    public int DistinctAccountThreshold { get; set; } = 3;
    public int DistinctIpThreshold { get; set; } = 3;

    public void Validate()
    {
        if (WindowMinutes <= 0 || FailureThreshold <= 0 ||
            DistinctAccountThreshold <= 0 || DistinctIpThreshold <= 0 ||
            RetentionMinutes < 2L * WindowMinutes ||
            StartupLookbackMinutes < WindowMinutes || StartupLookbackMinutes > RetentionMinutes)
            throw new ArgumentException("Detection thresholds must be positive; retention must be at least twice the window and contain the startup lookback.");
    }
}
