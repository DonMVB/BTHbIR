#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Identifies Active Directory accounts vulnerable to AS-REP Roasting.

.DESCRIPTION
    This script searches for user accounts that have Kerberos pre-authentication 
    disabled, making them vulnerable to AS-REP Roasting attacks. 

.PARAMETER ExportPath
    Optional path to export results as CSV file.
   
.EXAMPLE
    .\Detect-ASREPRoastable.ps1 -ExportPath "C:\Reports\asrep_vulnerable.csv"
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$ExportPath
)

Write-Host "`n=== AS-REP Roasting Vulnerability Scanner ===" -ForegroundColor Cyan
Write-Host "Scanning Active Directory for vulnerable accounts...`n" -ForegroundColor Yellow

try {
    # Query for accounts with pre-authentication disabled
    # DONT_REQ_PREAUTH flag = 0x400000 (4194304)
    $vulnAccounts = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true -and Enabled -eq $true} `
                                -Properties DoesNotRequirePreAuth, PasswordLastSet, LastLogonDate, Created, Description, UserAccountControl |
                    Select-Object Name, 
                                  SamAccountName, 
                                  UserPrincipalName,
                                  Enabled,
                                  DoesNotRequirePreAuth,
                                  PasswordLastSet,
                                  LastLogonDate,
                                  Created,
                                  Description,
                                  DistinguishedName,
                                  UserAccountControl
    
    if ($vulnAccounts) {
        $count = ($vulnAccounts | Measure-Object).Count
        Write-Host "[!] ALERT: Found $count vulnerable account(s):" -ForegroundColor Red
        Write-Host ("=" * 80) -ForegroundColor Red
        
        foreach ($account in $vulnAccounts) {
            Write-Host "`nAccount: $($account.SamAccountName)" -ForegroundColor Yellow
            Write-Host "  Name: $($account.Name)"
            Write-Host "  UPN: $($account.UserPrincipalName)"
            Write-Host "  Enabled: $($account.Enabled)"
            Write-Host "  Pre-Auth Required: NO (VULNERABLE)" -ForegroundColor Red
            Write-Host "  Password Last Set: $($account.PasswordLastSet)"
            Write-Host "  Last Logon: $($account.LastLogonDate)"
            Write-Host "  Created: $($account.Created)"
            Write-Host "  Description: $($account.Description)"
            Write-Host "  Distinguished Name: $($account.DistinguishedName)"
            Write-Host "  UAC Flags: $($account.UserAccountControl)"
        }
        
        Write-Host "`n" + ("=" * 80) -ForegroundColor Red
        Write-Host "[!] RECOMMENDATION: Enable Kerberos pre-authentication for these accounts" -ForegroundColor Yellow
        Write-Host "[*] Command to remediate: Set-ADAccountControl -Identity <username> -DoesNotRequirePreAuth `$false`n" -ForegroundColor Cyan
        
        # Export to CSV if path provided
        if ($ExportPath) {
            $vulnAccounts | Export-Csv -Path $ExportPath -NoTypeInformation
            Write-Host "[+] Results exported to: $ExportPath" -ForegroundColor Green
        }
        
    } else {
        Write-Host "[+] No vulnerable accounts found!" -ForegroundColor Green
        Write-Host "[+] All enabled accounts require Kerberos pre-authentication.`n" -ForegroundColor Green
    }
    
    # Additional statistics
    Write-Host "`n[*] Scan Statistics:" -ForegroundColor Cyan
    $totalUsers = (Get-ADUser -Filter {Enabled -eq $true}).Count
    Write-Host "    Total Enabled Users: $totalUsers"
    Write-Host "    Vulnerable Accounts: $count"
    
    if ($totalUsers -gt 0) {
        $percentage = [math]::Round(($count / $totalUsers) * 100, 2)
        Write-Host "    Vulnerability Rate: $percentage%"
    }
    
} catch {
    Write-Host "[!] Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "`n[*] Scan completed successfully`n" -ForegroundColor Green
