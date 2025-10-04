# Detect Kerberoasting Susceptable accounts and Activity
# Purpose: Identifies accounts vulnerable to Kerberoasting and detects active attacks
# Can be run by Domain Admins or users with appropriate audit log access

Import-Module ActiveDirectory

Write-Host "=== Kerberoasting Detection Script ===" -ForegroundColor Cyan
Write-Host "Analyzing Active Directory for Kerberoasting indicators...`n" -ForegroundColor Cyan

# Part 1: Find Vulnerable Accounts (Accounts with SPNs)
Write-Host "[1] Scanning for accounts with Service Principal Names..." -ForegroundColor Green

$VulnerableAccounts = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalNames, PasswordLastSet, msDS-SupportedEncryptionTypes, AdminCount, Enabled | 
    Where-Object {$_.SamAccountName -notlike "krbtgt*"}

if ($VulnerableAccounts) {
    Write-Host "[!] Found $($VulnerableAccounts.Count) accounts with SPNs (potentially vulnerable):" -ForegroundColor Yellow
    
    foreach ($Account in $VulnerableAccounts) {
        $EncType = $Account.'msDS-SupportedEncryptionTypes'
        $EncTypeString = switch ($EncType) {
            1 { "DES-CBC-CRC" }
            2 { "DES-CBC-MD5" }
            4 { "RC4-HMAC (VULNERABLE)" }
            8 { "AES128" }
            16 { "AES256" }
            24 { "AES128 + AES256" }
            default { "Not Set (defaults to RC4)" }
        }
        
        $DaysSincePasswordChange = if ($Account.PasswordLastSet) {
            (New-TimeSpan -Start $Account.PasswordLastSet -End (Get-Date)).Days
        } else {
            "Never"
        }
        
        Write-Host "`n  Account: $($Account.SamAccountName)" -ForegroundColor White
        Write-Host "    SPNs: $($Account.ServicePrincipalNames -join ', ')"
        Write-Host "    Encryption Type: $EncTypeString"
        Write-Host "    Password Last Set: $($Account.PasswordLastSet) ($DaysSincePasswordChange days ago)"
        Write-Host "    Privileged Account: $(if ($Account.AdminCount -eq 1) {'YES - HIGH RISK'} else {'No'})"
        Write-Host "    Enabled: $($Account.Enabled)"
    }
} else {
    Write-Host "[+] No non-system accounts with SPNs found" -ForegroundColor Green
}

# Part 2: Check Event Logs for Kerberoasting Activity
Write-Host "`n[2] Analyzing Security Event Logs for Kerberoasting indicators..." -ForegroundColor Green

try {
    # Look for Event ID 4769 (Kerberos Service Ticket requests) with RC4 encryption
    $StartTime = (Get-Date).AddHours(-24)  # Last 24 hours
    
    Write-Host "  Searching for suspicious TGS requests (last 24 hours)..." -ForegroundColor Yellow
    
    $SuspiciousEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id = 4769
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue | ForEach-Object {
        $EventXml = [xml]$_.ToXml()
        
        # Safely extract values from XML
        $TicketEncryption = ($EventXml.Event.EventData.Data | Where-Object {$_.Name -eq 'TicketEncryptionType'}).'#text'
        $ServiceName = ($EventXml.Event.EventData.Data | Where-Object {$_.Name -eq 'ServiceName'}).'#text'
        $AccountName = ($EventXml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
        $IpAddress = ($EventXml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'}).'#text'
        
        # RC4 = 0x17 (23), DES = 0x03 (3)
        # Filter out computer accounts and only show RC4 encrypted tickets
        if ($TicketEncryption -eq '0x17' -and $ServiceName -and $ServiceName -notlike '*$*') {
            [PSCustomObject]@{
                TimeCreated = $_.TimeCreated
                AccountName = $AccountName
                ServiceName = $ServiceName
                EncryptionType = "RC4 (0x17)"
                IpAddress = $IpAddress
            }
        }
    }
    
    if ($SuspiciousEvents) {
        Write-Host "[!] Found $($SuspiciousEvents.Count) suspicious TGS requests with RC4 encryption:" -ForegroundColor Red
        
        # Group by account and service to identify patterns
        $GroupedEvents = $SuspiciousEvents | Group-Object AccountName | Sort-Object Count -Descending
        
        foreach ($Group in $GroupedEvents) {
            Write-Host "`n  Requesting Account: $($Group.Name)" -ForegroundColor Yellow
            Write-Host "    Total Requests: $($Group.Count)"
            Write-Host "    Targeted Services:"
            $Group.Group | Select-Object ServiceName, TimeCreated, IpAddress -Unique | Format-Table -AutoSize | Out-String | Write-Host
        }
        
        Write-Host "[!] Multiple RC4 TGS requests may indicate Kerberoasting attack!" -ForegroundColor Red
    } else {
        Write-Host "[+] No suspicious TGS requests detected in the last 24 hours" -ForegroundColor Green
    }
    
} catch {
    Write-Host "[-] Error reading event logs: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "    Ensure you have appropriate permissions and are running on a Domain Controller or system with forwarded logs" -ForegroundColor Yellow
}

# Part 3: Recommendations
Write-Host "`n[3] Remediation Recommendations:" -ForegroundColor Cyan
Write-Host "  • Upgrade service accounts to use AES256 encryption"
Write-Host "  • Use Managed Service Accounts (MSA/gMSA) where possible"
Write-Host "  • Implement long, complex passwords (25+ characters) for service accounts"
Write-Host "  • Monitor Event ID 4769 for unusual patterns"
Write-Host "  • Enable advanced audit policy: Audit Kerberos Service Ticket Operations"
Write-Host "  • Consider removing unnecessary SPNs from user accounts"
Write-Host "`n=== Scan Complete ===" -ForegroundColor Cyan
