# vcf-ops-backup

Automate the export of VMware Aria Operations content.

This PowerShell 7 script provides a scheduled backup mechanism for Aria Operations configuration, since Aria Ops does not include a native scheduled backup feature (…whhhyyy??!). This script fills the gap by exporting content, saving it locally or optionally uploading it remotely to an SFTP server.

---

## Features
- Authenticate to Aria Ops via API using credentials stored in Vault.
- Submit and monitor export jobs until completion.
- Download the resulting `.zip` backup file.
- Apply retention policy to delete older backups automatically.
- Upload backups to an SFTP server using credentials retrieved from Vault.
- Log every step for diagnostics.
- Optional email notifications for success/failure.

---

# PowerShell Script: aops-content-export.ps1

## Phases
- 1.  Write timestamped messages into log
- 2.  Perform initial checks for completeness
- 3.  Ignore server certificate errors in PS Core (Linux)
- 4.  Authenticate to Vault via AppRole
- 5.  Retrieve AriaOps credentials from Vault
- 6.  Validate AriaOps parameters
- 7.  Authenticate to AriaOps API
- 8.  Build export payload
- 9.  Submit export job request
- 10. Poll and download ZIP
- 11. Retention cleanup for backup files
- 12. Send email notification with log file attached

---

## Requirements
- **PowerShell 7+** (tested on Linux and Windows runners).
- **Posh-SSH module** (for SFTP upload).
- **Vault connectivity** (AppRole or JWT authentication).
- CI/CD environment variables for Vault and SFTP credentials.

---

## Parameters

| Parameter               | Description                                                                    |
|-------------------------|--------------------------------------------------------------------------------|
| **AriaOpsURL**          | Base URL for Aria Ops API calls (must begin with `https://`).                  |
| **AuthSource**          | Authentication source (e.g. `Local`, `ActiveDirectory`, `vIDMAuthSource`).     |
| **Username**            | Aria Ops username (retrieved from Vault if not passed directly).               |
| **Password**            | Aria Ops password (retrieved from Vault if not passed directly).               |
| **ExportPassword**      | Password applied to the exported `.zip` file. *(Note: API may ignore this.)*   |
| **DownloadPath**        | Local directory where backup files will be saved.                              |
| **RetentionDays**       | Number of days to keep backups. Older files are deleted automatically.         |
| **LogFile**             | Path to the log file for progress and error messages.                          |
| **VaultAddr**           | URL of your Vault server (must begin with `https://`).                         |
| **RoleId**              | Vault AppRole Role ID (CI/CD variable).                                        |
| **SecretId**            | Vault AppRole Secret ID (CI/CD variable).                                      |
| **VaultPath**           | KV path in Vault where AriaOps credentials are stored.                         |
| **SftpServer**          | SFTP server alias name (CI/CD variable).                                       |
| **SftpPort**            | SFTP port number (default: 22).                                                |
| **RemotePath**          | SFTP server backup folder path.                                                |
| **VaultPathSftp**       | KV path in Vault where SFTP credentials are stored.                            |
| **EmailServer**         | SMTP server name for environment.                                              |
| **EmailTo**             | Comma‑separated list of email recipients.                                      |
| **VaultUsernameField**  | Field name in Vault secret containing AriaOps username (default: `user`).      |
| **VaultPasswordField**  | Field name in Vault secret containing AriaOps password (default: `pass`).      |
| **VaultExportPwdField** | Field name in Vault secret containing export password (default: `exportPass`). |

---

## Example Usage

```powershell
.\aops-content-export.ps1 `
    -AriaOpsURL https://ariaops.example.com `
    -AuthSource Local `
    -DownloadPath "C:\Backups\AriaOps" `
    -RetentionDays 14 `
    -LogFile "C:\Backups\AriaOps\export.log" `
    -VaultAddr https://vault.example.com `
    -RoleId $env:VAULT_ROLE_ID `
    -SecretId $env:VAULT_SECRET_ID `
    -VaultPath secret/data/<path>/ariaops `
    -SftpServer sftp_server `
    -SftpPort 22 `
    -RemotePath /backups/ariaops `
    -VaultPathSftp secret/data/<path>/sftp `
    -EmailServer smtp.example.com `
    -EmailTo ariaops.team@example.com
