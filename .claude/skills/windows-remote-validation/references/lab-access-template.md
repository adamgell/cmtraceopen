# Lab Access Template

Record these for each lab host in your local SSH config and lab notes. Real values
stay out of the repository.

## Access contract

- SSH alias: `<alias>`
- Address: `<lab-address>`
- Remote account: `<lab-account>`
- Local identity file: `<ssh-identity-file>`
- Hostname observed over SSH: `<host>`
- Windows shell: `powershell.exe` (Windows PowerShell 5.1)

## Client configuration

```sshconfig
Host <alias>
  HostName <lab-address>
  User <lab-account>
  IdentityFile <ssh-identity-file>
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new
```

## ConfigMgr site server evidence surface

- Site-server log root: `C:\Program Files\Microsoft Configuration Manager\Logs`
- ConfigMgr version and product ID: `HKLM:\SOFTWARE\Microsoft\SMS\Setup`
- `C:\Windows\CCM\Logs` is absent when the server is not also a ConfigMgr client.
- Expected running services include `SMS_EXECUTIVE`, `SMS_NOTIFICATION_SERVER`,
  `SMS_SITE_COMPONENT_MANAGER`, `SMS_SITE_SQL_BACKUP`, and `SMS_SITE_VSS_WRITER`.
- `SMS_SITE_BACKUP` may be stopped between backup runs; check the site-backup
  configuration before classifying it as a fault or changing it.

## Known quoting lesson

Complex inline commands fail when passed through multiple shells, especially around
PowerShell strings containing parentheses, `$`, backticks, and nested quotes. The
working pattern: write a `.ps1` locally, `scp` it to
`C:/Users/<lab-account>/AppData/Local/Temp/`, then invoke it with
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File ...`.
