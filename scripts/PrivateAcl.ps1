# Wspólna funkcja ustawiająca prawa do plików i katalogów. Zostawia dostęp kontu SYSTEM i administratorom. Korzystają z niej skrypty instalacji i konfiguracji hasła.

# Shared installer helper: replace the path's permissions with access for only
# SYSTEM (the service account) and Administrators. Other local users must not
# modify privileged service binaries or read the encrypted credential/outbox.
function Set-OsoPrivateAcl {
    param([Parameter(Mandatory = $true)][string]$Path, [switch]$Directory)
    if ($Directory) {
        # Directory permissions are inherited by both child folders and child files.
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    } else {
        # A file has no children, so inheritance flags are not needed.
        $acl = New-Object Security.AccessControl.FileSecurity
        $inheritance = [Security.AccessControl.InheritanceFlags]::None
    }
    # Block permissions inherited from the parent; use a fresh ACL to remove old explicit grants too.
    $acl.SetAccessRuleProtection($true, $false)
    # SID values work on all Windows languages: S-1-5-18 = SYSTEM, S-1-5-32-544 = Administrators.
    foreach ($sidText in @('S-1-5-18', 'S-1-5-32-544')) {
        $sid = New-Object Security.Principal.SecurityIdentifier($sidText)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
