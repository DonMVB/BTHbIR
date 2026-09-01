#Requires -RunAsAdministrator
# ***************************************************************************
# *  Script      : create_test_L3_wmi_V_01.ps1
# *  Version     : V_01
# *  Last Update : 2026-07-31 07:34 EST
# *  Purpose     : Level 3 synthetic check for Get-WMISubscriptions.
# *                Creates all THREE WMI persistence objects (__EventFilter,
# *                LogFileEventConsumer, __FilterToConsumerBinding) using an
# *                impossible trigger (Hour=25) so the subscription exists but
# *                NEVER fires. Run in powershell.exe (5.1), NOT pwsh.
# *  Admin       : REQUIRED (WMI root\subscription namespace).
# *  Logging     : Appends to create_test_L3_wmi_V_01.log beside script.
# *  Options     : (default) Create  |  -Remove  |  -WhatIf
# * Copyright (c) 2026, Don Murdoch, Blue Team Handbook
# ***************************************************************************
[CmdletBinding(SupportsShouldProcess=$true)]
param([switch]$Remove)

$Namespace    = 'root\subscription'
$FilterName   = 'ASEP_Synthetic_L3_Filter'
$ConsumerName = 'ASEP_Synthetic_L3_Consumer'
$LogFile      = if ($PSCommandPath) { $PSCommandPath -replace '\.ps1$','.log' } else { "create_test_L3_wmi_V_01.log" }
$FilterQuery  = "SELECT * FROM __InstanceModificationEvent WITHIN 3600 " +
                "WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 25"

function Write-Log { param([string]$M)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; $tz = [TimeZoneInfo]::Local.StandardName
    Add-Content -LiteralPath $LogFile -Value "$ts | $tz | $M" -ErrorAction SilentlyContinue }

if (-not (Get-Command Set-WmiInstance -ErrorAction SilentlyContinue)) {
    Write-Error "Classic WMI cmdlets not available. Run in powershell.exe (5.1), not pwsh."; return }

if ($Remove) {
    Write-Host "[*] Removing L3 WMI synthetic check..." -ForegroundColor Yellow
    $b = Get-WmiObject -Namespace $Namespace -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue |
         Where-Object { $_.Filter -match [regex]::Escape($FilterName) }
    if ($b) { if ($PSCmdlet.ShouldProcess("Binding","Remove")) { $b | Remove-WmiObject; Write-Host "  [+] Binding removed" -ForegroundColor Green } }
    $f = Get-WmiObject -Namespace $Namespace -Class __EventFilter -Filter "Name='$FilterName'" -ErrorAction SilentlyContinue
    if ($f) { if ($PSCmdlet.ShouldProcess($FilterName,"Remove filter")) { $f | Remove-WmiObject; Write-Host "  [+] Filter removed" -ForegroundColor Green } }
    $c = Get-WmiObject -Namespace $Namespace -Class LogFileEventConsumer -Filter "Name='$ConsumerName'" -ErrorAction SilentlyContinue
    if ($c) { if ($PSCmdlet.ShouldProcess($ConsumerName,"Remove consumer")) { $c | Remove-WmiObject; Write-Host "  [+] Consumer removed" -ForegroundColor Green } }
    Write-Log "REMOVED | L3 WMISubscriptions | filter=$FilterName consumer=$ConsumerName"
    return
}

Write-Host "[*] Creating L3 WMI synthetic check..." -ForegroundColor Yellow
if (Get-WmiObject -Namespace $Namespace -Class __EventFilter -Filter "Name='$FilterName'" -ErrorAction SilentlyContinue) {
    Write-Warning "Filter '$FilterName' already exists. Run -Remove first."; return }
if (-not $PSCmdlet.ShouldProcess($Namespace,"Create WMI filter/consumer/binding")) { return }

$F = Set-WmiInstance -Namespace $Namespace -Class __EventFilter -Arguments @{
    Name=''; EventNamespace='root\cimv2'; QueryLanguage='WQL'; Query=$FilterQuery } -ErrorAction Stop
# patch Name (WMI quirk with automatic Name property)
$F = Set-WmiInstance -Namespace $Namespace -Class __EventFilter -Arguments @{
    Name=$FilterName; EventNamespace='root\cimv2'; QueryLanguage='WQL'; Query=$FilterQuery }
Write-Host "  [+] Created __EventFilter        : $FilterName" -ForegroundColor Green
$C = Set-WmiInstance -Namespace $Namespace -Class LogFileEventConsumer -Arguments @{
    Name=$ConsumerName; Filename="$env:TEMP\ASEP_L3_WMI_synthetic.log"
    Text='ASEP synthetic WMI subscription (should never fire).' }
Write-Host "  [+] Created LogFileEventConsumer : $ConsumerName" -ForegroundColor Green
$null = Set-WmiInstance -Namespace $Namespace -Class __FilterToConsumerBinding -Arguments @{ Filter=$F; Consumer=$C }
Write-Host "  [+] Created __FilterToConsumerBinding" -ForegroundColor Green
Write-Log "ENABLED | L3 WMISubscriptions | filter=$FilterName consumer=$ConsumerName (trigger=impossible)"
Write-Host "[+] Run analyzer at -Level 3; look for '$FilterName' in WMI Subscriptions." -ForegroundColor Cyan
Write-Host "    Remove: .\create_test_L3_wmi_V_01.ps1 -Remove" -ForegroundColor DarkGray
