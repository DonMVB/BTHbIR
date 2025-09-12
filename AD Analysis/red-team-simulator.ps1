# ====================================================================
# ACTIVE DIRECTORY ATTACK SIMULATOR - Red Team Activity Generator
# ====================================================================
# WARNING: FOR AUTHORIZED TESTING ONLY - DO NOT USE IN PRODUCTION
# This script creates detectable attack artifacts for IR testing

# PREREQUISITES AND WARNINGS
# Install-Module ActiveDirectory
# Ensure you have Domain Admin rights for some tests
# Run only in test/lab environments with proper authorization

# Initialize environment and create directories
$hostname = $env:COMPUTERNAME
$timestamp = Get-Date -Format "yyyyMMdd.HHmmss"
$baseDir = "C:\IR"
$hostDir = "$baseDir\$hostname"
$demoDir = "$hostDir\ADDemo"

# Create directories if they don't exist
if (!(Test-Path $baseDir)) {
    New-Item -ItemType Directory -Path $baseDir -Force | Out-Null
    Write-Host "Created directory: $baseDir" -ForegroundColor Green
}

if (!(Test-Path $hostDir)) {
    New-Item -ItemType Directory -Path $hostDir -Force | Out-Null
    Write-Host "Created directory: $hostDir" -ForegroundColor Green
}

if (!(Test-Path $demoDir)) {
    New-Item -ItemType Directory -Path $demoDir -Force | Out-Null
    Write-Host "Created directory: $demoDir" -ForegroundColor Green
}

Write-Host "Active Directory Attack Simulator" -ForegroundColor Red
Write-Host "WARNING: FOR AUTHORIZED TESTING ONLY" -ForegroundColor Yellow
Write-Host "Output files will be saved to: $demoDir" -ForegroundColor Cyan
Write-Host "Timestamp format: $timestamp" -ForegroundColor Cyan

# Function to write output with error handling
function Write-DemoOutput {
    param(
        [string]$Topic,
        [scriptblock]$ScriptBlock,
        [string]$Description,
        [string]$Risk = "MEDIUM"
    )
    
    $outputFile = "$demoDir\$timestamp.$hostname.ADdemo$Topic.txt"
    Write-Host "Simulating: $Description" -ForegroundColor Yellow
    
    try {
        $result = & $ScriptBlock
        
        # Create output with header
        $output = @"
ACTIVE DIRECTORY ATTACK SIMULATION - $Description
Generated: $(Get-Date)
Hostname: $hostname
Topic: ADdemo$Topic
Risk Level: $Risk
Status: SUCCESS

SIMULATION ACTIVITIES PERFORMED:
$($result | Out-String)

DETECTION GUIDANCE:
This simulation created artifacts that should be detectable by the IR script.
Review the corresponding detection script output for these indicators.

END OF SIMULATION REPORT - $Description
"@
        
        $output | Out-File -FilePath $outputFile -Encoding UTF8
        Write-Host "  ✓ Simulation completed - log saved to: $(Split-Path $outputFile -Leaf)" -ForegroundColor Green
        
    } catch {
        # Write error information to file
        $errorOutput = @"
ACTIVE DIRECTORY ATTACK SIMULATION - $Description
Generated: $(Get-Date)
Hostname: $hostname  
Topic: ADdemo$Topic
Risk Level: $Risk
Status: ERROR

ERROR OCCURRED DURING SIMULATION:

Error Message: $($_.Exception.Message)
Error Line: $($_.InvocationInfo.ScriptLineNumber)
Error Position: $($_.InvocationInfo.OffsetInLine)
Error Command: $($_.InvocationInfo.Line.Trim())

Full Error Details:
$($_ | Out-String)

IMPACT:
Simulation failed - attack artifacts may not have been created properly.
This could indicate permission issues or environmental constraints.

END OF ERROR REPORT - $Description  
"@
        
        $errorOutput | Out-File -FilePath $outputFile -Encoding UTF8
        Write-Host "  ✗ Simulation failed - details saved to: $(Split-Path $outputFile -Leaf)" -ForegroundColor Red
    }
}

# 1. SIMULATE DCSYNC ATTACK PREPARATION
Write-DemoOutput -Topic "DCSync" -Risk "HIGH" -Description "DCSync Attack Simulation - Creating Suspicious Permissions" -ScriptBlock {
    Write-Output "Creating test user account for DCSync simulation..."
    
    # Create test user account
    $testUser = "ADdemoUser_$(Get-Random -Maximum 9999)"
    $testPassword = ConvertTo-SecureString "TempPass123!" -AsPlainText -Force
    
    try {
        New-ADUser -Name $testUser -SamAccountName $testUser -AccountPassword $testPassword -Enabled $true -Description "Temporary test account for AD simulation"
        Write-Output "Created test user: $testUser"
        
        # Simulate adding replication permissions (this will be detected)
        $domainDN = (Get-ADRootDSE).defaultNamingContext
        Write-Output "Domain DN: $domainDN"
        Write-Output "User DN: $(Get-ADUser $testUser).DistinguishedName"
        
        # Note: Actually granting DCSync permissions would be dangerous
        # Instead, we'll create log entries that simulate the attempt
        Write-Output "SIMULATION: Would grant 'Replicating Directory Changes' permission to $testUser"
        Write-Output "SIMULATION: Would grant 'Replicating Directory Changes All' permission to $testUser"
        Write-Output "SIMULATION: This should be detected by ACL analysis in the IR script"
        
        # Create a service account with SPN for additional detection
        $svcUser = "ADdemoSvc_$(Get-Random -Maximum 9999)"
        New-ADUser -Name $svcUser -SamAccountName $svcUser -AccountPassword $testPassword -Enabled $true -ServicePrincipalNames "HTTP/$svcUser.domain.local" -Description "Service account for AD simulation"
        Write-Output "Created service account with SPN: $svcUser"
        
        return @{
            TestUser = $testUser
            ServiceUser = $svcUser
            Status = "Created accounts for DCSync simulation"
        }
        
    } catch {
        Write-Output "Error creating test accounts: $($_.Exception.Message)"
        throw
    }
}

# 2. SIMULATE GOLDEN TICKET INDICATORS
Write-DemoOutput -Topic "GoldenTicket" -Risk "CRITICAL" -Description "Golden Ticket Attack Simulation - KRBTGT Analysis Triggers" -ScriptBlock {
    Write-Output "Simulating Golden Ticket attack indicators..."
    
    # Check KRBTGT account (this creates audit logs)
    $krbtgt = Get-ADUser krbtgt -Properties *
    Write-Output "Accessed KRBTGT account properties - this creates audit trail"
    Write-Output "KRBTGT Password Last Set: $($krbtgt.PasswordLastSet)"
    Write-Output "KRBTGT Password Age: $((Get-Date) - $krbtgt.PasswordLastSet)"
    
    # Simulate multiple Kerberos ticket requests
    Write-Output "Simulating suspicious Kerberos activity..."
    for ($i = 1; $i -le 5; $i++) {
        Write-Output "SIMULATION: Kerberos TGT request $i from unusual source"
        Write-Output "SIMULATION: This should generate Event ID 4768 entries"
        Start-Sleep -Seconds 2
    }
    
    # Create event log entries that would indicate Golden Ticket usage
    Write-Output "SIMULATION: Golden Ticket usage would show:"
    Write-Output "  - Kerberos authentication with forged timestamps"
    Write-Output "  - Unusual encryption types in tickets"
    Write-Output "  - Service access without corresponding TGT requests"
    Write-Output "  - Authentication from disabled/deleted accounts"
    
    return @{
        KRBTGTAccessed = $true
        SimulatedTicketRequests = 5
        Status = "Golden Ticket indicators simulated"
    }
}

# 3. SIMULATE SILVER TICKET PREPARATION
Write-DemoOutput -Topic "SilverTicket" -Risk "HIGH" -Description "Silver Ticket Attack Simulation - Service Account Targeting" -ScriptBlock {
    Write-Output "Simulating Silver Ticket attack preparation..."
    
    # Get service accounts for targeting simulation
    $serviceAccounts = Get-ADUser -Filter {servicePrincipalName -like "*"} | Select-Object -First 5
    Write-Output "Found $($serviceAccounts.Count) service accounts for simulation"
    
    foreach ($svcAccount in $serviceAccounts) {
        Write-Output "SIMULATION: Targeting service account - $($svcAccount.SamAccountName)"
        Write-Output "  Service Principal Names: $($svcAccount.servicePrincipalName -join ', ')"
        
        # Simulate service ticket requests (these will show in Event ID 4769)
        Write-Output "  SIMULATION: Requesting service ticket for $($svcAccount.SamAccountName)"
        Write-Output "  SIMULATION: This should generate Event ID 4769 with RC4 encryption"
    }
    
    # Create test service account vulnerable to Silver Ticket attack
    $vulnSvc = "ADdemoVulnSvc_$(Get-Random -Maximum 9999)"
    $testPassword = ConvertTo-SecureString "WeakServicePassword123" -AsPlainText -Force
    
    try {
        New-ADUser -Name $vulnSvc -SamAccountName $vulnSvc -AccountPassword $testPassword -Enabled $true -ServicePrincipalNames @("HTTP/$vulnSvc", "HOST/$vulnSvc") -PasswordNeverExpires $true
        
        # Set encryption type to RC4 only (vulnerable)
        Set-ADUser $vulnSvc -Replace @{"msDS-SupportedEncryptionTypes" = 4}
        
        Write-Output "Created vulnerable service account: $vulnSvc"
        Write-Output "  - Password never expires: True"
        Write-Output "  - Encryption: RC4 only (vulnerable)"
        Write-Output "  - SPNs: HTTP/$vulnSvc, HOST/$vulnSvc"
        
        return @{
            VulnerableServiceAccount = $vulnSvc
            TargetedAccounts = $serviceAccounts.Count
            Status = "Silver Ticket simulation completed"
        }
        
    } catch {
        Write-Output "Error creating vulnerable service account: $($_.Exception.Message)"
        throw
    }
}

# 4. SIMULATE VULNERABLE SERVICE ACCOUNT CONDITIONS
Write-DemoOutput -Topic "VulnerableAccounts" -Risk "MEDIUM" -Description "Vulnerable Service Account Creation" -ScriptBlock {
    Write-Output "Creating service accounts with security vulnerabilities..."
    
    $vulnerabilities = @()
    
    # Create account with old password date
    $oldPwdSvc = "ADdemoOldPwd_$(Get-Random -Maximum 9999)"
    $testPassword = ConvertTo-SecureString "OldPassword123!" -AsPlainText -Force
    
    try {
        New-ADUser -Name $oldPwdSvc -SamAccountName $oldPwdSvc -AccountPassword $testPassword -Enabled $true -ServicePrincipalNames "HTTP/$oldPwdSvc" -Description "Service account with old password simulation"
        
        # Simulate old password by setting pwdLastSet to past date
        $oldDate = (Get-Date).AddDays(-120).ToFileTime()
        Set-ADUser $oldPwdSvc -Replace @{"pwdLastSet" = $oldDate}
        
        Write-Output "Created service account with simulated old password: $oldPwdSvc"
        $vulnerabilities += "Old Password (120+ days)"
        
        # Create account with password never expires
        $neverExpireSvc = "ADdemoNeverExpire_$(Get-Random -Maximum 9999)"
        New-ADUser -Name $neverExpireSvc -SamAccountName $neverExpireSvc -AccountPassword $testPassword -Enabled $true -ServicePrincipalNames "MSSQL/$neverExpireSvc" -PasswordNeverExpires $true -Description "Service account with password never expires"
        
        Write-Output "Created service account with password never expires: $neverExpireSvc"
        $vulnerabilities += "Password Never Expires"
        
        # Create privileged service account (high risk)
        $privSvc = "ADdemoPrivSvc_$(Get-Random -Maximum 9999)"
        New-ADUser -Name $privSvc -SamAccountName $privSvc -AccountPassword $testPassword -Enabled $true -ServicePrincipalNames "LDAP/$privSvc"
        
        # Add to privileged group (simulation)
        Write-Output "SIMULATION: Adding $privSvc to Domain Admins (not actually performed)"
        Write-Output "Created privileged service account simulation: $privSvc"
        $vulnerabilities += "Privileged Service Account"
        
        # Create account with weak encryption
        $weakEncSvc = "ADdemoWeakEnc_$(Get-Random -Maximum 9999)"
        New-ADUser -Name $weakEncSvc -SamAccountName $weakEncSvc -AccountPassword $testPassword -Enabled $true -ServicePrincipalNames "HTTP/$weakEncSvc"
        Set-ADUser $weakEncSvc -Replace @{"msDS-SupportedEncryptionTypes" = 4} # RC4 only
        
        Write-Output "Created service account with weak encryption (RC4 only): $weakEncSvc"
        $vulnerabilities += "Weak Encryption (RC4 Only)"
        
        return @{
            CreatedAccounts = @($oldPwdSvc, $neverExpireSvc, $privSvc, $weakEncSvc)
            Vulnerabilities = $vulnerabilities
            Status = "Vulnerable service accounts created for detection testing"
        }
        
    } catch {
        Write-Output "Error creating vulnerable service accounts: $($_.Exception.Message)"
        throw
    }
}

# 5. SIMULATE CREDENTIAL DUMPING ACTIVITY
Write-DemoOutput -Topic "CredentialDumping" -Risk "CRITICAL" -Description "Credential Dumping Attack Simulation" -ScriptBlock {
    Write-Output "Simulating credential dumping attack indicators..."
    
    # Simulate NTDS.DIT access attempts
    Write-Output "SIMULATION: Attempting to access NTDS.DIT file"
    Write-Output "  Location: C:\Windows\NTDS\ntds.dit"
    Write-Output "  This should generate Event ID 4663 (File Access)"
    
    # Simulate Volume Shadow Copy creation
    Write-Output "SIMULATION: Creating Volume Shadow Copy for offline analysis"
    Write-Output "  Command simulated: vssadmin create shadow /for=C:"
    Write-Output "  This should generate System Event Log entries"
    
    try {
        # Create some files to simulate extraction tools
        $toolsDir = "$env:TEMP\ADdemoTools"
        if (!(Test-Path $toolsDir)) {
            New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
        }
        
        # Create fake mimikatz log
        $mimikatzLog = @"
SIMULATION: Mimikatz execution log
sekurlsa::logonpasswords attempted
This file simulates credential dumping tool artifacts
Created: $(Get-Date)
"@
        $mimikatzLog | Out-File "$toolsDir\debug.log" -Encoding UTF8
        Write-Output "Created simulated tool artifact: $toolsDir\debug.log"
        
        # Create fake NTDS extraction
        $ntdsExtract = @"
SIMULATION: NTDS.DIT extraction attempt
Database size: 50MB (simulated)
Records extracted: 1000+ (simulated)
This file simulates offline credential database extraction
"@
        $ntdsExtract | Out-File "$toolsDir\ntds_extract.txt" -Encoding UTF8
        Write-Output "Created simulated NTDS extraction log: $toolsDir\ntds_extract.txt"
        
        # Simulate registry hive extraction
        Write-Output "SIMULATION: Registry hive extraction"
        Write-Output "  SYSTEM hive: C:\Windows\System32\config\SYSTEM"
        Write-Output "  SAM hive: C:\Windows\System32\config\SAM"
        Write-Output "  SECURITY hive: C:\Windows\System32\config\SECURITY"
        
        # Create process that might trigger LSASS monitoring
        Write-Output "SIMULATION: Process access to LSASS.EXE"
        Write-Output "  This should generate Event ID 4656 (Process Access)"
        
        return @{
            SimulatedActivities = @(
                "NTDS.DIT access attempt",
                "Volume Shadow Copy creation", 
                "Tool artifacts created",
                "Registry hive access",
                "LSASS process access"
            )
            ArtifactLocation = $toolsDir
            Status = "Credential dumping simulation completed"
        }
        
    } catch {
        Write-Output "Error simulating credential dumping: $($_.Exception.Message)"
        throw
    }
}

# 6. SIMULATE DANGEROUS ACL MODIFICATIONS
Write-DemoOutput -Topic "DangerousACLs" -Risk "HIGH" -Description "Dangerous ACL Modification Simulation" -ScriptBlock {
    Write-Output "Simulating dangerous ACL modifications..."
    
    try {
        # Create test OU for ACL modifications
        $testOU = "OU=ADdemoTestOU_$(Get-Random -Maximum 9999),$((Get-ADRootDSE).defaultNamingContext)"
        New-ADOrganizationalUnit -Name "ADdemoTestOU_$(Get-Random -Maximum 9999)" -Path (Get-ADRootDSE).defaultNamingContext
        Write-Output "Created test OU for ACL simulation: $testOU"
        
        # Create test user to grant dangerous permissions
        $aclTestUser = "ADdemoACLUser_$(Get-Random -Maximum 9999)"
        $testPassword = ConvertTo-SecureString "TempPass123!" -AsPlainText -Force
        New-ADUser -Name $aclTestUser -SamAccountName $aclTestUser -AccountPassword $testPassword -Enabled $true
        
        Write-Output "Created test user for ACL simulation: $aclTestUser"
        
        # Simulate dangerous permission grants (not actually performed for safety)
        Write-Output "SIMULATION: Granting dangerous permissions to $aclTestUser"
        Write-Output "  - GenericAll on Domain root (not actually performed)"
        Write-Output "  - WriteDacl on AdminSDHolder (not actually performed)"
        Write-Output "  - Replicating Directory Changes (not actually performed)"
        Write-Output "  - Reset Password on Domain Admins group (not actually performed)"
        
        # Show what DSACLS commands would detect
        Write-Output "Detection commands that should find these changes:"
        Write-Output "  dsacls domain_dn | findstr /i $aclTestUser"
        Write-Output "  dsacls AdminSDHolder | findstr /i $aclTestUser"
        
        # Modify AdminCount to simulate privilege escalation
        Set-ADUser $aclTestUser -Replace @{"adminCount" = 1}
        Write-Output "Set AdminCount=1 for $aclTestUser (simulates privilege escalation)"
        
        return @{
            TestOU = $testOU
            TestUser = $aclTestUser
            SimulatedPermissions = @(
                "GenericAll on Domain",
                "WriteDacl on AdminSDHolder",
                "Replicating Directory Changes",
                "Reset Password on Domain Admins"
            )
            Status = "ACL modification simulation completed"
        }
        
    } catch {
        Write-Output "Error simulating ACL modifications: $($_.Exception.Message)"
        throw
    }
}

# 7. SIMULATE HIDDEN OBJECTS
Write-DemoOutput -Topic "HiddenObjects" -Risk "MEDIUM" -Description "Hidden Active Directory Objects Creation" -ScriptBlock {
    Write-Output "Creating hidden and suspicious AD objects..."
    
    try {
        $hiddenObjects = @()
        
        # Create user with suspicious name
        $suspiciousUser = '$ADdemoHidden_$(Get-Random -Maximum 9999)'
        $testPassword = ConvertTo-SecureString "HiddenPass123!" -AsPlainText -Force
        New-ADUser -Name $suspiciousUser -SamAccountName $suspiciousUser -AccountPassword $testPassword -Enabled $true -Description "password in description - temp123"
        
        # Hide user in advanced view
        Set-ADUser $suspiciousUser -Replace @{"ShowInAdvancedViewOnly" = $true}
        Write-Output "Created hidden user with suspicious naming: $suspiciousUser"
        $hiddenObjects += $suspiciousUser
        
        # Create user with misleading name/description
        $misleadingUser = "ADdemoBackupSvc_$(Get-Random -Maximum 9999)"
        New-ADUser -Name $misleadingUser -SamAccountName $misleadingUser -AccountPassword $testPassword -Enabled $true -Description "admin account for backup operations" -DisplayName "Backup Service"
        
        # Add to unusual OU by moving it
        Write-Output "Created misleading service account: $misleadingUser"
        $hiddenObjects += $misleadingUser
        
        # Create disabled account with recent changes
        $disabledUser = "ADdemoDisabled_$(Get-Random -Maximum 9999)"
        New-ADUser -Name $disabledUser -SamAccountName $disabledUser -AccountPassword $testPassword -Enabled $false -Description "temporary disabled account"
        
        # Modify it to appear recently changed
        Set-ADUser $disabledUser -Replace @{"Comment" = "Modified $(Get-Date)"}
        Write-Output "Created recently modified disabled account: $disabledUser"
        $hiddenObjects += $disabledUser
        
        # Create user with unusual characters
        $weirdUser = "~ADdemo_test$(Get-Random -Maximum 999)"
        New-ADUser -Name $weirdUser -SamAccountName $weirdUser -AccountPassword $testPassword -Enabled $true -Description "test account with unusual naming"
        Write-Output "Created user with unusual naming pattern: $weirdUser"
        $hiddenObjects += $weirdUser
        
        # Create user in unusual location (if possible)
        try {
            $unusualUser = "ADdemoUnusual_$(Get-Random -Maximum 9999)"
            New-ADUser -Name $unusualUser -SamAccountName $unusualUser -AccountPassword $testPassword -Enabled $true -Path "CN=Users,$((Get-ADRootDSE).defaultNamingContext)"
            Write-Output "Created user in unusual location: $unusualUser"
            $hiddenObjects += $unusualUser
        } catch {
            Write-Output "Could not create user in unusual location: $($_.Exception.Message)"
        }
        
        return @{
            HiddenObjects = $hiddenObjects
            DetectionPoints = @(
                "ShowInAdvancedViewOnly = True",
                "Suspicious naming patterns",
                "Recent modifications on disabled accounts",
                "Misleading descriptions",
                "Unusual character usage"
            )
            Status = "Hidden objects simulation completed"
        }
        
    } catch {
        Write-Output "Error creating hidden objects: $($_.Exception.Message)"
        throw
    }
}

# 8. SIMULATE KERBEROASTING SETUP
Write-DemoOutput -Topic "Kerberoasting" -Risk "HIGH" -Description "Kerberoasting Attack Simulation Setup" -ScriptBlock {
    Write-Output "Setting up Kerberoasting attack simulation..."
    
    try {
        # Create service accounts vulnerable to Kerberoasting
        $kerbVulnAccounts = @()
        
        for ($i = 1; $i -le 3; $i++) {
            $kerbUser = "ADdemoKerbSvc$i_$(Get-Random -Maximum 999)"
            $testPassword = ConvertTo-SecureString "ServicePassword$i!" -AsPlainText -Force
            
            New-ADUser -Name $kerbUser -SamAccountName $kerbUser -AccountPassword $testPassword -Enabled $true -ServicePrincipalNames "HTTP/$kerbUser.domain.local"
            
            # Set to use RC4 encryption (vulnerable to Kerberoasting)
            Set-ADUser $kerbUser -Replace @{"msDS-SupportedEncryptionTypes" = 23} # RC4 + AES (but RC4 preferred)
            
            Write-Output "Created Kerberoastable service account: $kerbUser"
            $kerbVulnAccounts += $kerbUser
        }
        
        # Create account vulnerable to ASREPRoasting
        $asrepUser = "ADdemoASREP_$(Get-Random -Maximum 9999)"
        $testPassword = ConvertTo-SecureString "NoPreAuthPass123!" -AsPlainText -Force
        New-ADUser -Name $asrepUser -SamAccountName $asrepUser -AccountPassword $testPassword -Enabled $true
        
        # Disable Kerberos pre-authentication (vulnerable to ASREPRoasting)
        Set-ADAccountControl -Identity $asrepUser -DoesNotRequirePreAuth $true
        Write-Output "Created ASREPRoastable account: $asrepUser"
        
        # Simulate Kerberoasting attack requests
        Write-Output "SIMULATION: Requesting service tickets for Kerberoasting"
        foreach ($account in $kerbVulnAccounts) {
            Write-Output "  SIMULATION: Request RC4 service ticket for $account"
            Write-Output "    This should generate Event ID 4769 with encryption type 0x17 (RC4)"
        }
        
        Write-Output "SIMULATION: ASREPRoasting attempt on $asrepUser"
        Write-Output "  This should generate Event ID 4768 without pre-authentication"
        
        return @{
            KerberoastableAccounts = $kerbVulnAccounts
            ASREPRoastableAccount = $asrepUser
            VulnerabilityTypes = @(
                "Service accounts with RC4 encryption",
                "Accounts without Kerberos pre-authentication required"
            )
            Status = "Kerberoasting simulation setup completed"
        }
        
    } catch {
        Write-Output "Error setting up Kerberoasting simulation: $($_.Exception.Message)"
        throw
    }
}

# 9. SIMULATE SUSPICIOUS AUTHENTICATION PATTERNS
Write-DemoOutput -Topic "AuthAnomalies" -Risk "MEDIUM" -Description "Suspicious Authentication Pattern Simulation" -ScriptBlock {
    Write-Output "Simulating suspicious authentication patterns..."
    
    try {
        # Create accounts for authentication testing
        $authTestUsers = @()
        
        for ($i = 1; $i -le 3; $i++) {
            $authUser = "ADdemoAuth$i_$(Get-Random -Maximum 999)"
            $testPassword = ConvertTo-SecureString "AuthTest$i!" -AsPlainText -Force
            New-ADUser -Name $authUser -SamAccountName $authUser -AccountPassword $testPassword -Enabled $true
            $authTestUsers += $authUser
            Write-Output "Created authentication test user: $authUser"
        }
        
        # Simulate failed authentication attempts
        Write-Output "SIMULATION: Multiple failed authentication attempts"
        Write-Output "  These should generate Event ID 4625 (Failed Logon)"
        foreach ($user in $authTestUsers) {
            for ($attempt = 1; $attempt -le 5; $attempt++) {
                Write-Output "    SIMULATION: Failed logon attempt $attempt for $user"
            }
        }
        
        # Simulate privilege escalation
        $privEscUser = $authTestUsers[0]
        Set-ADUser $privEscUser -Replace @{"adminCount" = 1}
        Write-Output "SIMULATION: Privilege escalation for $privEscUser (adminCount set to 1)"
        Write-Output "  This should generate Event ID 4672 (Special Privilege Assigned)"
        
        # Simulate unusual logon times
        Write-Output "SIMULATION: Authentication outside business hours"
        Write-Output "  Time: $(Get-Date -Hour 2 -Minute 30)"
        Write-Output "  Source: Unusual workstation/IP address"
        Write-Output "  This should generate Event ID 4624 (Successful Logon)"
        
        # Simulate lateral movement indicators
        Write-Output "SIMULATION: Lateral movement authentication patterns"
        Write-Output "  Multiple systems accessed in short time period"
        Write-Output "  Network logons from administrative accounts"
        Write-Output "  Service logons from user accounts"
        
        return @{
            TestUsers = $authTestUsers
            PrivilegeEscalationUser = $privEscUser
            SimulatedPatterns = @(
                "Multiple failed authentications",
                "Privilege escalation events", 
                "Off-hours authentication",
                "Lateral movement patterns"
            )
            Status = "Authentication anomaly simulation completed"
        }
        
    } catch {
        Write-Output "Error simulating authentication anomalies: $($_.Exception.Message)"
        throw
    }
}

# 10. CLEANUP FUNCTION
Write-DemoOutput -Topic "Cleanup" -Risk "LOW" -Description "Attack Simulation Cleanup Instructions" -ScriptBlock {
    Write-Output "Attack simulation cleanup instructions and summary..."
    
    Write-Output "CREATED OBJECTS FOR CLEANUP:"
    
    # List all demo users created
    $demoUsers = Get-ADUser -Filter {Description -like "*demo*" -or SamAccountName -like "ADdemo*"}
    if ($demoUsers) {
        Write-Output "Demo Users Created ($($demoUsers.Count)):"
        $demoUsers | ForEach-Object { Write-Output "  - $($_.SamAccountName) ($($_.Name))" }
    }
    
    # List demo OUs created
    $demoOUs = Get-ADOrganizationalUnit -Filter {Name -like "ADdemoTestOU*"}
    if ($demoOUs) {
        Write-Output "Demo OUs Created ($($demoOUs.Count)):"
        $demoOUs | ForEach-Object { Write-Output "  - $($_.Name)" }
    }
    
    Write-Output "CLEANUP COMMANDS:"
    Write-Output "# Remove demo users:"
    if ($demoUsers) {
        $demoUsers | ForEach-Object { Write-Output "Remove-ADUser -Identity '$($_.SamAccountName)' -Confirm:`$false" }
    }
    
    Write-Output "# Remove demo OUs:"
    if ($demoOUs) {
        $demoOUs | ForEach-Object { Write-Output "Remove-ADOrganizationalUnit -Identity '$($_.DistinguishedName)' -Confirm:`$false" }
    }
    
    Write-Output "# Remove demo files:"
    Write-Output "Remove-Item '$env:TEMP\ADdemoTools' -Recurse -Force -ErrorAction SilentlyContinue"
    
    Write-Output "DETECTION VERIFICATION:"
    Write-Output "Run the AD Incident Response script to verify these artifacts are detected:"
    Write-Output "  - Service accounts with vulnerabilities"
    Write-Output "  - Hidden user accounts"  
    Write-Output "  - Suspicious ACL modifications"
    Write-Output "  - Authentication anomalies"
    Write-Output "  - Kerberoasting setup"
    Write-Output "  - Credential dumping indicators"
    
    Write-Output "TIMELINE FOR TESTING:"
    Write-Output "1. Run this attack simulator script"
    Write-Output "2. Wait 5-10 minutes for events to populate logs"
    Write-Output "3. Run the AD Incident Response detection script"
    Write-Output "4. Compare detection results with simulation artifacts"
    Write-Output "5. Run cleanup commands to remove test objects"
