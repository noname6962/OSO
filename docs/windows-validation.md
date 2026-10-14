# Windows 11 functional validation

Run these checks on the local test VM. Use a disposable test account and ensure you have a working administrator session; account lockout policies can interrupt failure generation. Do not test against other machines.

## Auditing and prerequisites

In `secpol.msc`, open **Advanced Audit Policy Configuration > System Audit Policies > Logon/Logoff** and enable:

- Audit Logon: Success and Failure (4624/4625).
- Audit Logoff: Success (4634/4647).
- Audit Special Logon: Success (4672).

These names are localized in non-English Windows. Domain policy can override local settings; check the effective policy with `auditpol /get /category:*`. Confirm the expected records actually appear in Security. Events 4634/4647 and source IP availability depend on the logon mechanism, so not every login yields all fields/IDs. Only records that Windows generates can be collected.

Install the service following README.md, confirm configuration validation succeeds, and inspect operational entries for `Startup replay completed; monitoring Security log.`

## Required checks

1. **Below-threshold behavior:** Generate four failed logins for a fresh test account within five minutes. Verify four 4625 records exist and no alert was generated for that account. Avoid accidental extra failures from unrelated software using the account.
2. **Threshold and no grouping:** Generate the fifth and sixth failures. Verify two distinct alert IDs in warning entries with event ID 1000 and two emails. Both contain the relevant failure evidence. Missing IPs must not prevent account detection.
3. **Success after failures:** Successfully log in as that account while the failure pattern remains within five minutes. Verify a new alert includes `SuccessAfter:RepeatedAccountFailures`, the 4624 record and its logon type. A success more than five minutes after the final qualifying failures should not trigger that rule.
4. **Supporting context:** Log off and perform further controlled test logins. Verify available 4634/4647/4672 records related to subsequent alerts are included. Already emitted alerts are not revised with future logoffs.
5. **Startup replay and deduplication:** Stop the service, generate a fresh threshold sequence, then start it within ten minutes. Verify the sequence is analyzed. Restart again and confirm records already delivered do not produce another email. New qualifying records must still produce alerts.
6. **Email recovery:** Temporarily block outbound SMTP for this executable using a reversible test firewall rule. Generate a qualifying event and confirm its warning and pending `ProgramData\OSO\outbox` record exist. Remove only your test rule. Verify email delivery resumes; the existing warning is not rewritten during an ordinary retry.
7. **Restart recovery:** With an email pending, restart the service, restore SMTP access, and verify the persisted alert is delivered with its original ID/evidence.
8. **Retention:** Wait more than ten minutes with no events. Automated tests verify idle history expiry; on Windows, verify old records are excluded from evidence in a later alert and stored warnings remain available. Delivered outbox records contain metadata only; pending deliveries may still contain evidence.

The cross-platform test suite validates multi-account/IP rules using fixtures. Real IP-based Windows validation needs controlled network logins to this VM from the corresponding distinct source addresses; local interactive logins often have no source IP. Do not claim those Windows paths verified without such records.

## Troubleshooting

- No 4625: check effective auditing and whether the login mechanism generates this event locally.
- Startup failure: run the executable with `--validate-config` as administrator; inspect file permissions and Event Log source registration.
- Gmail failure: inspect operational errors; verify two-step verification, App Password, sender address, outbound TLS access, and credential-file ACLs. Never attach the password file or raw credentials to diagnostics.
- Corrupt state: stop the service and preserve the affected outbox files before investigation. Do not delete pending evidence just to make the service start.
- Recovery cannot replay downtime exceeding ten minutes. Extend the configured lookback/retention if you need a longer outage window; this MVP has no permanent Security-log cursor.

Record actual pass/fail results, event IDs and alert IDs for your VM. Compilation and unit tests in a Linux cloud machine do not establish Windows functional readiness.
