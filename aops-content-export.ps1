<#
.SYNOPSIS
    Exports VMware Aria Operations content using credentials stored in Vault via AppRole.

.DESCRIPTION
    1. Ignore server certificate errors in PS Core (Linux).
    2. Authenticates to Vault using AppRole (RoleID/SecretID).
    3. Retrieves AriaOps API credentials (username, password) and export encryption password.
    4. Acquires an AriaOps API token.
    5. Submits a content‐export job, polls for completion, downloads the ZIP.
    6. Cleans up old export files based on retention days.
    7. Logs every step to the specified log file.

.OUTPUTS
    This PowerShell script produces a ZIP file and a log file.

.PARAMETER AriaOpsURL
    Base URL of your Aria Operations instance (must begin with https://).

.PARAMETER AuthSource
    Authentication source in AriaOps (e.g. "Local" or "ActiveDirectory").

.PARAMETER DownloadPath
    Local directory where export ZIP files will be saved.

.PARAMETER RetentionDays
    Number of days to keep old export files before deleting.

.PARAMETER LogFile
    Path to the log file for writing progress and errors.

.PARAMETER VaultAddr
    URL of your Vault server (must begin with https://).

.PARAMETER RoleId
    Vault AppRole Role ID (provided as a CI/CD variable).

.PARAMETER SecretId
    Vault AppRole Secret ID (provided as a CI/CD variable).

.PARAMETER VaultPath
    KV path in Vault where AriaOps credentials are stored (e.g. "secret/data/<path>/ariaops").

.PARAMETER SftpServer
    SFTP server alias name (provided as a CI/CD variable).

.PARAMETER SftpPort
    SFTP port number (provided as a CI/CD variable).

.PARAMETER RemotePath
    SFTP server backup folder path (provided as a CI/CD variable).

.PARAMETER VaultPathSftp
    KV path in Vault where SFTP backup credentials are stored (e.g. "secret/data/<path>/sftp").

.PARAMETER EmailServer
    SMTP server name for environment (provided as a CI/CD variable).

.PARAMETER EmailTo
    Email recipient(s) for environment (provided as a CI/CD variable).

.PARAMETER VaultUsernameField
    Field name in the secret containing the AriaOps username. Defaults to "user".

.PARAMETER VaultPasswordField
    Field name in the secret containing the AriaOps password. Defaults to "pass".

.PARAMETER VaultExportPwdField
    Field name in the secret containing the export‐encryption password. Defaults to "exportPass".

.NOTES
    GitLab pipeline schedule: Daily runs @ 7:00am NZST
    Artifact retention: 14 days as agreed with Aria Ops team
    Email notification: Currently only sends to ariaops.team@example.com (testing)
#>

param (
    [Parameter(Mandatory=$true)] [string] $AriaOpsURL       = $env:CI_AOPS_URI,
    [Parameter(Mandatory=$true)] [string] $AuthSource       = $env:AUTH_SOURCE,
    [Parameter(Mandatory=$true)] [string] $DownloadPath     = $env:DOWNLOAD_PATH,
    [Parameter(Mandatory=$true)] [int]    $RetentionDays    = $env:RETENTION_DAYS,
    [Parameter(Mandatory=$true)] [string] $LogFile          = $env:LOG_FILE,

    [Parameter(Mandatory=$true)] [string] $VaultAddr        = $env:VAULT_ADDR,
    [Parameter(Mandatory=$true)] [string] $RoleId,
    [Parameter(Mandatory=$true)] [string] $SecretId,
    [Parameter(Mandatory=$true)] [string] $VaultPath        = $env:VAULT_PATH,

    [string] $SftpServer            = $env:SFTP_SERVER,
    [string] $SftpPort              = $env:SFTP_PORT,
    [string] $RemotePath            = $env:SFTP_PATH,
    [string] $VaultPathSftp         = $env:VAULT_PATH_SFTP,

    [string] $EmailServer           = $env:CI_SMTP_SERVER,
    [string] $EmailTo               = $env:EMAIL_REPORT,

    [string] $VaultUsernameField    = 'user',
    [string] $VaultPasswordField    = 'pass',
    [string] $VaultExportPwdField   = 'exportPass'
)

#--------------------------
# 1. Write timestamped messages into log
#--------------------------
function Write-Log {
    param([string] $Message)
    if (-not $LogFile) {
        Write-Log "LogFile parameter is not set. Exiting."
        exit 1
    }
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$ts - $Message" | Out-File -FilePath $LogFile -Append
}

Write-Log "==== Starting Aria Ops export via Vault AppRole ===="

#--------------------------
# 2. Perform initial checks for completeness
#--------------------------
try {
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $tcpClient.Connect($SftpServer, 22)
    Write-Log "Port 22 is reachable."
    $tcpClient.Close()
} catch {
    Write-Log "Port 22 is NOT reachable: $_.Exception.Message"
}

# Ensure Posh-SSH is available
if (-not (Get-Module -ListAvailable -Name Posh-SSH)) {
    Write-Log "Posh-SSH module not found. Installing..."
    try {
        Install-Module -Name Posh-SSH -Force -Scope CurrentUser -ErrorAction Stop
        Write-Log "Posh-SSH installed successfully."
    }
    catch {
        Write-Log "Failed to install Posh-SSH: $_.Exception.Message"
        throw "SFTP module installation failed. Cannot proceed with upload."
    }
}

Import-Module Posh-SSH -ErrorAction Stop

Write-Log "Available SFTP cmdlets:"
$cmdlets = Get-Command -Module Posh-SSH | Where-Object { $_.Name -like '*SFTP*' } | Select-Object -ExpandProperty Name
foreach ($c in $cmdlets) {
    Write-Log " - $c"
}

Write-Log "PSModulePath: $env:PSModulePath"

#--------------------------
# 3. Ignore server certificate errors in PS Core (Linux)
#--------------------------
$PSDefaultParameterValues = @{
  'Invoke-RestMethod:SkipCertificateCheck' = $true
  'Invoke-WebRequest:SkipCertificateCheck' = $true
}
Write-Log "WARNING: Skipping SSL certificate validation for REST calls"

[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

#--------------------------
# 4. Authenticate to Vault via AppRole
#--------------------------
$loginUri = "$VaultAddr/v1/auth/approle/login"
$loginBody = @{ role_id = $RoleId; secret_id = $SecretId } | ConvertTo-Json
Write-Log "Logging in to Vault AppRole at $loginUri"
try {
    $loginResp = Invoke-RestMethod -Uri $loginUri -Method Post `
                  -Body $loginBody -ContentType 'application/json'
    $vaultToken = $loginResp.auth.client_token
    Write-Log "Vault authentication token successfully acquired."
} catch {
    Write-Log "Vault AppRole login failed: $_"
    exit 1
}

Write-Log "Calling AriaOps token endpoint: $loginUri"

#--------------------------
# 5. Retrieve AriaOps credentials from Vault
#--------------------------
$secretUri = "$VaultAddr/v1/$VaultPath"
Write-Log "Fetching secrets from Vault..."
try {
    $secResp = Invoke-RestMethod -Uri $secretUri -Method Get `
                 -Headers @{ 'X-Vault-Token' = $vaultToken }
    $data = $secResp.data.data
    $Username       = $data.$VaultUsernameField
    $Password       = $data.$VaultPasswordField
    $ExportPassword = $data.$VaultExportPwdField
    Write-Log "Secrets loaded for user $Username."
} catch {
    Write-Log "Failed to read secrets: $_"
    exit 1
}

#--------------------------
# 6. Validate AriaOps parameters
#--------------------------
if (-not ($AriaOpsURL -match '^https?://')) {
    Write-Log "Invalid Aria Ops URI: $AriaOpsURL"
    exit 1
}
if (-not (Test-Path $DownloadPath)) { New-Item -ItemType Directory -Path $DownloadPath | Out-Null }
Write-Log "DownloadPath: $DownloadPath  RetentionDays: $RetentionDays"

# One‐off helper to enumerate auth‐sources
$SourceUri = "$AriaOpsURL/suite-api/api/auth/sources"
$sources   = Invoke-RestMethod -Uri $SourceUri -Method Get -Headers @{ Authorization = "OpsToken $Token" }
Write-Log "Available AuthSources: $($sources | ConvertTo-Json -Depth 2)"

#--------------------------
# 7. Authenticate to AriaOps API
#--------------------------
# Force TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$loginUri = "$($AriaOpsURL.TrimEnd('/'))/suite-api/api/auth/token/acquire"
$loginData = @{ username = $Username; authSource = $AuthSource; password = $Password } | ConvertTo-Json -Depth 10

Write-Log "Calling AriaOps token endpoint: $loginUri"

Write-Log "Sending authentication request with body (password obfuscated)..."
try {
    $AuthResp = Invoke-RestMethod -Uri $loginUri -Method POST -Body $loginData -ContentType "application/json;charset=UTF-8" -Headers @{ "Accept"="application/json" } -ErrorAction Stop
    $Token = $AuthResp.token
    Write-Log "Vault authentication token successfully acquired."
} catch {
    Write-Log "Error during authentication: $_.Exception.Message"
    Write-Log "Response: $_"
    exit 1
}

#--------------------------
# 8. Build export payload
#--------------------------
# Create content management export job
$ExportPayload = @{ 
    scope = "ALL"
    contentTypes = @(
        "VIEW_DEFINITIONS", "REPORT_DEFINITIONS", "DASHBOARDS", "REPORT_SCHEDULES", "POLICIES", 
        "ALERT_DEFINITIONS", "SYMPTOM_DEFINITIONS", "RECOMMENDATION_DEFINITIONS", "CUSTOM_GROUPS", 
        "CUSTOM_METRICGROUPS", "SUPER_METRICS", "CONFIG_FILES", "COMPLIANCE_SCORECARDS", "NOTIFICATION_RULES", 
        "OUTBOUND_SETTINGS", "PAYLOAD_TEMPLATES", "INTEGRATIONS", "USERS", "USER_GROUPS", "ROLES", 
        "AUTH_SOURCES", "HTTP_PROXIES", "COST_DRIVERS", "SDMP_CUSTOM_SERVICES", "SDMP_CUSTOM_APPLICATIONS", 
        "CUSTOM_PROFILES", "DISCOVERY_RULES", "APP_DEF_ASSIGNMENTS", "GLOBAL_SETTINGS"
    )
} | ConvertTo-Json -Depth 10
 
Write-Log "Export Payload: $ExportPayload"

#--------------------------
# 9. Submit export job request
#--------------------------
$ExportUri = "$AriaOpsURL/suite-api/api/content/operations/export?_no_links=true"
Write-Log "Sending export request to Aria Ops..."
# Validate payload structure
try {
    $ExportJobResponse = Invoke-RestMethod -Uri $ExportUri -Method Post -Headers @{
        "Authorization" = "OpsToken $Token";
        "EncryptionPassword" = $ExportPassword;
        "Content-Type" = "application/json;charset=UTF-8"
    } -Body $ExportPayload -ErrorAction Stop
 
} catch {
    Write-Log "Export job creation failed: $_.Exception.Message"
    Write-Log "Response: $_"
    exit 1
}

#--------------------------
# 10. Poll and download ZIP
#--------------------------
# Retry download until successful for maximum of 10 times
$JobCompleted = $false
$DownloadAttempts = 0
$MaxDownloadAttempts = 10

while (-not $JobCompleted -and $DownloadAttempts -lt $MaxDownloadAttempts) {
    $DownloadAttempts++
    Write-Log "Attempting to download backup. Attempt #$DownloadAttempts"

    $DownloadUrl = "$AriaOpsURL/suite-api/api/content/operations/export/zip?_no_links=true"
    $ExportFileName = "AriaOpsBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"
    $ExportFilePath = Join-Path -Path $DownloadPath -ChildPath $ExportFileName

    try {
        Write-Log "Downloading backup from: $DownloadUrl"
        Invoke-WebRequest -Uri $DownloadUrl -Headers @{ Authorization = "OpsToken $Token" } -OutFile $ExportFilePath -ErrorAction Stop
        Write-Log "Backup file downloaded successfully: $ExportFilePath"
        $JobCompleted = $true

        if ($JobCompleted) {
            Write-Log "Authenticating to Vault using AppRole and retrieving SFTP credentials..."

            $RoleId   = $env:VAULT_ROLE_ID
            $SecretId = $env:VAULT_SECRET_ID

            if ([string]::IsNullOrWhiteSpace($RoleId) -or [string]::IsNullOrWhiteSpace($SecretId)) {
                Write-Log "Vault AppRole credentials missing, cannot authenticate."
                throw "Missing VAULT_ROLE_ID or VAULT_SECRET_ID"
            }

            $VaultCredPath  = $env:VAULT_PATH_SFTP  # e.g., "secret/data/per2/mx7000"
            $VaultLoginUri  = "$VaultAddr/v1/auth/approle/login"
            $VaultLoginBody = @{ role_id = $RoleId; secret_id = $SecretId } | ConvertTo-Json

            try {
                # --- Vault authentication ---
                $VaultLoginResponse = Invoke-RestMethod -Method POST -Uri $VaultLoginUri -Body $VaultLoginBody -ContentType "application/json"
                $VaultToken = $VaultLoginResponse.auth.client_token
                Write-Log "Vault authentication token successfully acquired."

                $VaultHeaders = @{ "X-Vault-Token" = $VaultToken }
                $VaultResponse = Invoke-RestMethod -Method GET -Uri "$VaultAddr/v1/$VaultCredPath" -Headers $VaultHeaders -ErrorAction Stop

                if (-not $VaultResponse.data -or -not $VaultResponse.data.data -or -not $VaultResponse.data.data.user -or -not $VaultResponse.data.data.pass) {
                    Write-Log "Vault secret missing expected fields. Check path and permissions."
                    throw "Vault secret at '$VaultCredPath' is missing 'user' or 'pass'."
                }

                $SftpUser    = $VaultResponse.data.data.user
                $SftpPassRaw = $VaultResponse.data.data.pass

                if ([string]::IsNullOrWhiteSpace($SftpPassRaw)) {
                    Write-Log "Vault response missing password. Cannot proceed with password-based SFTP."
                    throw "Vault secret missing 'password' field"
                }

                $SftpPass = $SftpPassRaw | ConvertTo-SecureString -AsPlainText -Force
                $SftpCred = New-Object System.Management.Automation.PSCredential ($SftpUser, $SftpPass)
            }
            catch {
                Write-Log "Vault authentication or secret retrieval failed: $_.Exception.Message"
                throw
            }

            try {
                # --- SFTP upload ---
                Write-Log "Uploading backup to SFTP server: $SftpServer"
                $Session = New-SFTPSession -ComputerName $SftpServer -Credential $SftpCred -Port $SftpPort -AcceptKey

                # Build today's prefix (date only)
                $TodayPrefix = "AriaOpsBackup_{0}" -f (Get-Date -Format 'yyyyMMdd')

                # List remote files in the backup directory
                $RemoteFiles = Get-SFTPChildItem -SessionId $Session.SessionId -Path $RemotePath

                if ($RemoteFiles.Name -like "$TodayPrefix*") {
                    Write-Log "A backup for today ($TodayPrefix) already exists on remote host, skipping upload."
                } else {
                    Write-Log "No backup for today found, proceeding with upload..."
                    if (Get-Command Set-SFTPFile -ErrorAction SilentlyContinue) {
                        Set-SFTPFile -SessionId $Session.SessionId -LocalFile $ExportFilePath -RemotePath $RemotePath
                    } else {
                        Set-SFTPItem -SessionId $Session.SessionId -Path $ExportFilePath -Destination $RemotePath
                    }
                    Write-Log "SFTP upload complete: $RemotePath/$ExportFileName"
                }
            }
            catch {
                Write-Log "SFTP upload failed: $_.Exception.Message"
                throw
            }
        }
    }
    catch {
        Write-Log "Error downloading backup: $_.Exception.Message"
        Write-Log "Response: $_"
        Start-Sleep -Seconds 30
    }
}

if (-not $JobCompleted) {
    Write-Log "Download failed after $MaxDownloadAttempts attempts."
    exit 1
}

#--------------------------
# 11. Retention cleanup for backup files
#--------------------------
# Backup retention management - drop files older than the $RetentionDays argument
Write-Log "Cleaning up files older than $RetentionDays days (day-based check)."

# Calculate cutoff date
$RetentionDate = (Get-Date).AddDays(-$RetentionDays).Date

# Get all backup files matching the naming pattern
$session = New-SFTPSession -ComputerName $SftpServer -Port $SftpPort -Credential $SftpCred -AcceptKey
$allFiles = Get-SFTPChildItem -SFTPSession $session -Path $RemotePath

$oldFiles = foreach ($file in $allFiles) {
    $remove = $false

    Write-Log "Evaluating file: $($file.Name)"

    # Parse only the YYYYMMDD portion from filename
    if ($file.Name -match 'AriaOpsBackup_(\d{8})_.*\.zip') {
        try {
            $fileDate = [datetime]::ParseExact($matches[1], 'yyyyMMdd', $null).Date
            Write-Log " -> Parsed filename date: $fileDate"

            # Compare just the day
            if ($fileDate -le $RetentionDate) {
                Write-Log " -> Filename date is older than or equal to cutoff ($RetentionDate)"
                $remove = $true
            }
        } catch {
            Write-Log " -> Could not parse date from filename: $($file.Name)"
        }
    } else {
        Write-Log " -> Filename did not match expected pattern..."
    }

    if ($remove) { $file }
}

if ($oldFiles) {
    foreach ($file in $oldFiles) {
        Write-Log "Removing old backup file: $($file.FullName)"
        Remove-SFTPItem -SessionId $session.SessionId -Path $file.FullName -Force
    }
    Write-Log "Retention cleanup complete: $($oldFiles.Count) file(s) removed."
} else {
    Write-Log "No backup files older than $RetentionDays days were found."
}

# Close session after all removals
if ($session -and $session.SessionId) {
    Remove-SFTPSession -SessionId $session.SessionId
    Write-Log "SFTP session closed."
}

Write-Log "==== Aria Ops content export and backup script process completed successfully ===="

#--------------------------
# 12. Send email notification with log file attached
#--------------------------
Write-Log "Sending report to $EmailTo via $EmailServer."
try {
    Send-MailMessage -From "ariaops.team@example.com" `
                     -To $EmailTo `
                     -Subject $AriaOpsURL `
                     -Body "Attached are the logs for: $AriaOpsURL.`n`nAria Ops content export and backup script process completed successfully." `
                     -Attachments $LogFile `
                     -SmtpServer $EmailServer
    Write-Log "Report sent successfully."
}
catch {
    Write-Log "Failed to send report: $($_.Exception.Message)"
}

exit 0
