#Requires -RunAsAdministrator
#Requires -Module ActiveDirectory

<#
.SYNOPSIS
    Configures Active Directory auditing settings based on CIS recommendations
.DESCRIPTION
    This script configures audit policies for Active Directory based on Center for Internet Security (CIS) 
    recommendations. It includes process creation auditing (Event 4688) with command line detail tracking.
.NOTES
    - Must be run as Administrator
    - Requires Active Directory PowerShell module
    - Based on CIS Microsoft Windows Server 2019 Benchmark
    - Creates backup of current settings before applying changes
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$BackupCurrentSettings = $true,
    [string]$BackupPath = "C:\Temp\ADaudit_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
)

# Function to log actions
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $(
        switch($Level) {
            "ERROR" { "Red" }
            "WARNING" { "Yellow" }
            "SUCCESS" { "Green" }
            default { "White" }
        }
    )
}

# Function to backup current audit settings
function Backup-CurrentAuditSettings {
    param([string]$Path)
    
    Write-Log "Creating backup of current audit settings..."
    try {
        $backupContent = @()
        $backupContent += "=== Current Audit Policy Settings - $(Get-Date) ==="
        $backupContent += ""
        
        # Get current audit policy settings
        $auditpol = & auditpol /get /category:* 2>$null
        $backupContent += $auditpol
        
        # Get current registry settings
        $backupContent += ""
        $backupContent += "=== Registry Settings ==="
        
        # Process Creation Command Line
        try {
            $cmdLineAudit = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue
            $backupContent += "ProcessCreationIncludeCmdLine_Enabled: $($cmdLineAudit.ProcessCreationIncludeCmdLine_Enabled)"
        } catch {
            $backupContent += "ProcessCreationIncludeCmdLine_Enabled: Not set"
        }
        
        $backupContent | Out-File -FilePath $Path -Encoding UTF8
        Write-Log "Backup saved to: $Path" -Level "SUCCESS"
    }
    catch {
        Write-Log "Failed to create backup: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
    return $true
}

# Function to configure audit policies
function Set-AuditPolicy {
    param([string]$Category, [string]$Setting)
    
    try {
        Write-Log "Setting $Category to $Setting"
        $result = & auditpol /set /category:"$Category" /$Setting 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Successfully configured: $Category" -Level "SUCCESS"
        } else {
            Write-Log "Failed to configure $Category : $result" -Level "ERROR"
        }
    }
    catch {
        Write-Log "Error configuring $Category : $($_.Exception.Message)" -Level "ERROR"
    }
}

# Function to configure audit subcategories
function Set-AuditSubcategory {
    param([string]$Subcategory, [string]$Setting)
    
    try {
        Write-Log "Setting $Subcategory to $Setting"
        $result = & auditpol /set /subcategory:"$Subcategory" /$Setting 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Successfully configured: $Subcategory" -Level "SUCCESS"
        } else {
            Write-Log "Failed to configure $Subcategory : $result" -Level "ERROR"
        }
    }
    catch {
        Write-Log "Error configuring $Subcategory : $($_.Exception.Message)" -Level "ERROR"
    }
}

# Main execution
Write-Log "Starting CIS Active Directory Audit Configuration"
Write-Log "Script must be run as Administrator on a Domain Controller"

# Check if running as administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "This script must be run as Administrator" -Level "ERROR"
    exit 1
}

# Check if Active Directory module is available
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Log "Active Directory module loaded successfully"
}
catch {
    Write-Log "Active Directory module not available. Please install RSAT-AD-PowerShell feature" -Level "ERROR"
    exit 1
}

# Create backup directory if needed
if ($BackupCurrentSettings) {
    $backupDir = Split-Path $BackupPath -Parent
    if (!(Test-Path $backupDir)) {
        New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
    }
    
    if (!(Backup-CurrentAuditSettings -Path $BackupPath)) {
        Write-Log "Backup failed. Continue anyway? (Y/N): " -Level "WARNING"
        $response = Read-Host
        if ($response -ne 'Y' -and $response -ne 'y') {
            Write-Log "Exiting due to backup failure" -Level "ERROR"
            exit 1
        }
    }
}

Write-Log "Configuring CIS recommended audit policies..."

# CIS Benchmark Audit Policy Recommendations
Write-Log "=== Account Logon ==="
Set-AuditSubcategory -Subcategory "Credential Validation" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Kerberos Authentication Service" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Kerberos Service Ticket Operations" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Other Account Logon Events" -Setting "success,failure"

Write-Log "=== Account Management ==="
Set-AuditSubcategory -Subcategory "Application Group Management" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Computer Account Management" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Distribution Group Management" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Other Account Management Events" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Security Group Management" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "User Account Management" -Setting "success,failure"

Write-Log "=== Detailed Tracking ==="
Set-AuditSubcategory -Subcategory "DPAPI Activity" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Process Creation" -Setting "success" # Event 4688
Set-AuditSubcategory -Subcategory "Process Termination" -Setting "success"
Set-AuditSubcategory -Subcategory "RPC Events" -Setting "success,failure"

Write-Log "=== DS Access ==="
Set-AuditSubcategory -Subcategory "Detailed Directory Service Replication" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Directory Service Access" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Directory Service Changes" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Directory Service Replication" -Setting "success,failure"

Write-Log "=== Logon/Logoff ==="
Set-AuditSubcategory -Subcategory "Account Lockout" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Group Membership" -Setting "success"
Set-AuditSubcategory -Subcategory "IPsec Extended Mode" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "IPsec Main Mode" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "IPsec Quick Mode" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Logoff" -Setting "success"
Set-AuditSubcategory -Subcategory "Logon" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Network Policy Server" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Other Logon/Logoff Events" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Special Logon" -Setting "success"

Write-Log "=== Object Access ==="
Set-AuditSubcategory -Subcategory "Application Generated" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Certification Services" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Detailed File Share" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "File Share" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "File System" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Filtering Platform Connection" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Filtering Platform Packet Drop" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Handle Manipulation" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Kernel Object" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Other Object Access Events" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Registry" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Removable Storage" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "SAM" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Central Policy Staging" -Setting "success,failure"

Write-Log "=== Policy Change ==="
Set-AuditSubcategory -Subcategory "Audit Policy Change" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Authentication Policy Change" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Authorization Policy Change" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Filtering Platform Policy Change" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "MPSSVC Rule-Level Policy Change" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Other Policy Change Events" -Setting "success,failure"

Write-Log "=== Privilege Use ==="
Set-AuditSubcategory -Subcategory "Non Sensitive Privilege Use" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Other Privilege Use Events" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Sensitive Privilege Use" -Setting "success,failure"

Write-Log "=== System ==="
Set-AuditSubcategory -Subcategory "IPsec Driver" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Other System Events" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Security State Change" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "Security System Extension" -Setting "success,failure"
Set-AuditSubcategory -Subcategory "System Integrity" -Setting "success,failure"

# Configure Process Creation Command Line Auditing (for Event 4688 details)
Write-Log "=== Configuring Process Creation Command Line Auditing ==="
try {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    
    # Create registry path if it doesn't exist
    if (!(Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    
    # Enable command line process auditing
    Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord
    Write-Log "Process Creation Command Line Auditing enabled" -Level "SUCCESS"
}
catch {
    Write-Log "Failed to enable Process Creation Command Line Auditing: $($_.Exception.Message)" -Level "ERROR"
}

# Configure Advanced Audit Policy to override legacy settings
Write-Log "=== Configuring Advanced Audit Policy Override ==="
try {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-ItemProperty -Path $regPath -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord
    Write-Log "Advanced Audit Policy override enabled" -Level "SUCCESS"
}
catch {
    Write-Log "Failed to enable Advanced Audit Policy override: $($_.Exception.Message)" -Level "ERROR"
}

Write-Log "=== Configuration Complete ==="
Write-Log "Active Directory audit configuration completed based on CIS recommendations"
Write-Log "Event 4688 (Process Creation) auditing enabled with command line details"

if ($BackupCurrentSettings) {
    Write-Log "Backup of previous settings saved to: $BackupPath"
}

Write-Log "Please review the Event Viewer Security log to verify events are being generated"
Write-Log "Consider configuring log size and retention policies as needed"
Write-Log "Restart may be required for all settings to take effect"

# Display current audit policy summary
Write-Log "=== Current Audit Policy Summary ==="
try {
    & auditpol /get /category:* | Where-Object { $_ -notmatch "^$" -and $_ -notmatch "Category/Subcategory" -and $_ -notmatch "^Machine Name" }
}
catch {
    Write-Log "Could not retrieve current audit policy summary" -Level "WARNING"
}
