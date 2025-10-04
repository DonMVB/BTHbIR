# Script 1: Create Kerberoasting-Vulnerable Test Account
# Purpose: Creates a service account with SPN and RC4 encryption for testing/demonstration
# WARNING: This creates a deliberately vulnerable account - use only in test environments

# Requires Domain Admin or Account Operator privileges
# Run from a domain-joined machine with AD PowerShell module

Import-Module ActiveDirectory

# Variables
$AccountName = "backup01"
$AccountPassword = "ComplexPasswordGoesHere" # Change this to meet your password policy
$ServicePrincipalName = "HTTP/backup01.yourdomain.local" # Change to your domain
$OUPath = "OU=ServiceAccounts,DC=yourdomain,DC=local" # Change to your OU path

try {
    # Create the user account
    Write-Host "[+] Creating service account: $AccountName" -ForegroundColor Green
    
    $SecurePassword = ConvertTo-SecureString $AccountPassword -AsPlainText -Force
    
    New-ADUser -Name $AccountName `
        -SamAccountName $AccountName `
        -UserPrincipalName "$AccountName@yourdomain.local" `
        -AccountPassword $SecurePassword `
        -Enabled $true `
        -PasswordNeverExpires $true `
        -CannotChangePassword $false `
        -Path $OUPath `
        -Description "Backup Service Account - Test" `
        -ErrorAction Stop
    
    Write-Host "[+] Account created successfully" -ForegroundColor Green
    
    # Set the Service Principal Name
    Write-Host "[+] Setting Service Principal Name: $ServicePrincipalName" -ForegroundColor Green
    Set-ADUser -Identity $AccountName -ServicePrincipalNames @{Add=$ServicePrincipalName} -ErrorAction Stop
    
    Write-Host "[+] SPN set successfully" -ForegroundColor Green
    
    # Force RC4 encryption by setting msDS-SupportedEncryptionTypes to 4
    # Values: 1=DES-CBC-CRC, 2=DES-CBC-MD5, 4=RC4-HMAC, 8=AES128, 16=AES256
    Write-Host "[+] Configuring account to use RC4 encryption" -ForegroundColor Yellow
    
    Set-ADAccountControl -Identity $AccountName -DoesNotRequirePreAuth $false
    
    # Set encryption type to RC4 only
    Set-ADUser -Identity $AccountName -Replace @{"msDS-SupportedEncryptionTypes"=4}
    
    Write-Host "[+] RC4 encryption configured" -ForegroundColor Green
    
    # Display account information
    Write-Host "`n[+] Account Configuration Summary:" -ForegroundColor Cyan
    $User = Get-ADUser -Identity $AccountName -Properties ServicePrincipalNames, msDS-SupportedEncryptionTypes, PasswordNeverExpires
    
    Write-Host "  Account Name: $($User.SamAccountName)"
    Write-Host "  Distinguished Name: $($User.DistinguishedName)"
    Write-Host "  Service Principal Names: $($User.ServicePrincipalNames -join ', ')"
    Write-Host "  Encryption Types: $($User.'msDS-SupportedEncryptionTypes')"
    Write-Host "  Password Never Expires: $($User.PasswordNeverExpires)"
    
    Write-Host "`n[!] WARNING: This account is configured to be vulnerable to Kerberoasting" -ForegroundColor Red
    Write-Host "[!] Use only in controlled test environments" -ForegroundColor Red
    
} catch {
    Write-Host "[-] Error occurred: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
