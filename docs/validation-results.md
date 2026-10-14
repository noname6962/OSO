# Implementation validation

The initial implementation was verified in the Linux cloud workspace using .NET SDK **10.0.402**. This historical record describes checks performed before the repository was reduced to application/build/deployment files and documentation:

| Check | Result |
| --- | --- |
| Locked solution restore | Passed; package auditing/signature verification enabled |
| Release solution build | Passed; zero warnings and errors |
| Core test suite | 36 passed, 0 failed, 0 skipped |
| Windows x64 self-contained publish | Passed; generated `Oso.Service.exe` and runtime files |
| `scripts/Publish.ps1` execution | Passed; runs tests before locked Windows publish |
| All five PowerShell scripts parsed with PowerShell 7.5.4 | Passed |

PowerShell 7.5.4 was downloaded from the official release and checked against its published SHA256 manifest. Installation scripts target Windows PowerShell 5.1. The former remote CI workflow was not run during this validation and has now been removed along with the test project and solution file.

After cleanup, locked restore and Release build of `src/Oso.Service/Oso.Service.csproj` passed with zero warnings/errors. The simplified `scripts/Publish.ps1` also successfully published the self-contained Windows executable without a test dependency. The 36-test result above is historical; the test suite is not included in the trimmed repository.

**Not executed in this environment:** Windows service installation, effective auditing, live Security log subscription, Windows Event Log writes, DPAPI credential protection/decryption, Gmail authentication/delivery, Windows service recovery and Windows-specific file ACL operations.

Use [windows-validation.md](windows-validation.md) on the Windows 11 VM to complete these functional checks. No Gmail credentials are included in the repository or published files.
