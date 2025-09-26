# Run as Administrator
# this is a powershll utility script that sets up the 4688 event
# and also enables detailed tracking so that you can get
# the command line in the 4688 event itself.
# copyright 2025 Don Murdoch / Blue Team Handbook

Write-Host "Enabling Process Creation Auditing (Event ID 4688)..." -ForegroundColor Cyan

# Enable Audit Process Creation for Success
auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable

# Enable Command Line Auditing via registry
$regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
$regName = "ProcessCreationIncludeCmdLine_Enabled"

# Create key if missing
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set value to enable command line logging
Set-ItemProperty -Path $regPath -Name $regName -Value 1

Write-Host "Command Line Auditing enabled." -ForegroundColor Green

# Optional: Confirm settings
Write-Host "`nCurrent Audit Policy for Process Creation:"
auditpol /get /subcategory:"Process Creation"

Write-Host "`nRegistry setting for command line auditing:"
Get-ItemProperty -Path $regPath -Name $regName
