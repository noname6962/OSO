# Implementation validation

Verified in the Linux cloud workspace using .NET SDK **10.0.402**:

| Check | Result |
| --- | --- |
| Locked solution restore | Passed; package auditing/signature verification enabled |
| Release solution build | Passed; zero warnings and errors |
| Core test suite | 36 passed, 0 failed, 0 skipped |
| Windows x64 self-contained publish | Passed; generated `Oso.Service.exe` and runtime files |
| `scripts/Publish.ps1` execution | Passed; runs tests before locked Windows publish |
| All five PowerShell scripts parsed with PowerShell 7.5.4 | Passed |

PowerShell 7.5.4 was downloaded from the official release and checked against its published SHA256 manifest. Installation scripts target Windows PowerShell 5.1; the CI workflow includes parsing with that version on Windows, but the remote CI workflow has not been run here.

**Not executed in this environment:** Windows service installation, effective auditing, live Security log subscription, Windows Event Log writes, DPAPI credential protection/decryption, Gmail authentication/delivery, Windows service recovery and Windows-specific file ACL operations.

Use [windows-validation.md](windows-validation.md) on the Windows 11 VM to complete these functional checks. No Gmail credentials are included in the repository or published files.
