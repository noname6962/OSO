# OSO login monitor

A .NET 10 Windows Service for a local Windows 11 VM. It reads Security events **4624, 4625, 4634, 4647 and 4672**, detects suspicious login patterns, writes supporting evidence to **OSO-Warnings**, and sends Gmail notifications. Rules indicate suspicion, not proof of malicious activity.

## Behavior

The collector subscribes before replaying the preceding **10 minutes**, then continues live monitoring. XML is parsed by field name, independent of the Windows display language. Startup/live overlaps are deduplicated. Authentication methods that do not produce 4624/4625 are outside this MVP; domain-controller Kerberos/NTLM events are not collected.

The analyzer uses a **5-minute inclusive window**:

| Rule | Condition |
| --- | --- |
| Repeated account failures | At least 5 events 4625 against the same domain/account |
| One IP, multiple accounts | At least 5 failures from one IP across at least 3 accounts |
| Multiple IPs, one account | At least 5 failures against one account from at least 3 IPs |
| Success after failures | Event 4624 while a preceding qualifying pattern remains in the window; the successful account must have been targeted |

All available logon types are included; no account/IP exemptions are applied. Missing IPs participate in account rules but never become synthetic IPs. IPv4-mapped IPv6 addresses are normalized. Each new qualifying event generates one alert containing all matching rules: **no grouping or cooldown**. Several subsequent failures can therefore produce several emails. Replaying the *same* record is deduplication, not grouping.

Supporting evidence includes already collected related account/IP events and same-computer logon-session events, within the retained history. Future events cannot be included in an already emitted alert. Privilege and logoff records provide evidence; they do not independently trigger alerts. Out-of-order live records use their event timestamps; this MVP does not retrospectively revise an earlier alert when later evidence arrives.

Memory history expires after **10 minutes**, including during idle periods. Windows logs are never deleted. Pending delivery evidence is retained on disk until successful delivery; delivered records retain only a small identity marker for 24 hours to prevent duplicate alerts during restarts.

## Build and test

Install the .NET 10 SDK. From the repository root:

```powershell
dotnet restore OSO.sln --locked-mode
dotnet test tests/Oso.Tests/Oso.Tests.csproj -c Release --no-restore
dotnet build OSO.sln -c Release --no-restore
```

The core tests run on Linux or Windows. Event Log collection, DPAPI and Windows Service execution require Windows.

Publish a self-contained Windows x64 executable (the deployment machine needs no .NET runtime):

```powershell
.\scripts\Publish.ps1
```

## Install on the Windows VM

Use **Windows PowerShell 5.1 as administrator** for the installation scripts (`New-EventLog` is a Windows PowerShell cmdlet). If your execution policy prevents scripts, follow your machine's policy for signing/authorizing scripts rather than changing machine-wide policy.

1. Enable success/failure **Audit Logon**, success **Audit Logoff**, and success **Audit Special Logon**. Follow [the Windows validation guide](docs/windows-validation.md).
2. In the Gmail account, enable two-step verification and create an App Password. Account policies may disallow App Passwords; those accounts need a different sender or an OAuth implementation.
3. Store the App Password securely, then install:

```powershell
.\scripts\Set-GmailCredential.ps1
.\scripts\Install-Service.ps1 -GmailAddress 'monitor@gmail.com' -Recipient 'alerts@example.com'
```

Defaults: binaries under `C:\Program Files\OSO`, state under `C:\ProgramData\OSO`, Windows Service `OsoLoginMonitor`, warning log `OSO-Warnings`, source `OsoLoginMonitor`. The installer preserves existing nonempty installation directories and refuses to overwrite them.

The MVP runs as **LocalSystem** to read the Security log. Installation/state directories are restricted to SYSTEM and Administrators because the service runs with elevated privileges. Gmail credentials are encrypted using machine-bound Windows DPAPI, additionally protected by file ACLs. They are never stored in source or JSON configuration. Copying the encrypted file to another machine will not restore the credential.

Use a dedicated state directory; credential setup refuses a nonempty directory not marked as OSO-owned. To rotate the credential deliberately, rerun `Set-GmailCredential.ps1 -ReplaceExisting`.

Allow outbound **smtp.gmail.com:587** with STARTTLS (465 with TLS is also supported). Certificate verification stays enabled. Delivery failures are retried with exponential backoff, up to 5 minutes between attempts. A full/corrupt outbox or collection failure stops the service visibly; Windows recovery restarts it. The warning is persisted before email delivery. Large evidence is split into numbered warning entries with the same alert ID; email includes an XML attachment.

SMTP and Event Log cannot participate in one transaction. A process crash after an external write but before saving its completion marker can duplicate an entry/email. Delivery is **at least once**, not exactly once. Alert IDs and deterministic email Message-IDs help identify such duplicates.

## Configuration and operation

Defaults are in `src/Oso.Service/appsettings.json`; installed overrides are in `appsettings.Local.json` beside the executable. Environment overrides use `OSO_` and double underscores, e.g. `OSO_Detection__FailureThreshold`. Restart the service after editing configuration. Retention must be at least twice the detection window and contain the startup lookback.

```powershell
& 'C:\Program Files\OSO\Oso.Service.exe' --validate-config
Get-Service OsoLoginMonitor
Get-WinEvent -FilterHashtable @{ LogName = 'OSO-Warnings'; Id = 1000 } -MaxEvents 10
Restart-Service OsoLoginMonitor
.\scripts\Uninstall-Service.ps1
```

Configuration validation checks fields, credential decryption, registered warning source and Security read access; it does not authenticate Gmail or prove actual collection. Service startup alone is not functional validation. Use [docs/windows-validation.md](docs/windows-validation.md) to complete the Windows checks.

Uninstall preserves logs, credentials, delivery state and binaries. For updates, stop/uninstall, preserve the old binaries and local configuration, then install into an empty directory using the same data directory. Keep pending outbox records to retain delivery/replay state. The custom Windows log follows Windows retention settings; choose its capacity/overwrite policy to match your needs. Alert evidence and emails contain account/IP information, so restrict access to the log and recipient mailbox.
