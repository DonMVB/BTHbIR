# ====================================================================
# ACTIVE DIRECTORY INCIDENT RESPONSE - DCSync and Kerberos Attacks
# ====================================================================
# Run these commands on Domain Controllers or systems with appropriate AD tools
# Output files will be created in C:\IR\<hostname>\ directory

# PREREQUISITES - Install Required Modules
# =========================================
# Install-Module ActiveDirectory
# Install-Module DSInternals
# Download and install Sysinternals Suite

# Initialize environment and create directories
$hostname = $env:COMPUTERNAME
$timestamp = Get-Date -Format "yyyyMMdd.HHmmss"
$baseDir = "C:\IR"
$hostDir = "$baseDir\$hostname"

# Create directories if they don't exist
if (!(Test-Path $baseDir)) {
    New-Item -ItemType Directory -Path $baseDir -Force | Out-Null
    Write-Host "Created directory: $baseDir" -ForegroundColor Green
}

if (!(Test-Path $hostDir)) {
    New-Item -ItemType Directory -Path $hostDir -Force | Out-Null
    Write-Host "Created directory: $hostDir" -ForegroundColor Green
}

Write-Host "Active Directory Incident Response Script" -ForegroundColor Cyan
Write-Host "Output files will be saved to: $hostDir" -ForegroundColor Cyan
Write-Host "Timestamp format: $timestamp" -ForegroundColor Cyan

# Function to write output with error handling
function Write-IROutput {
    param(
        [string]$Topic,
        [scriptblock]$ScriptBlock,
        [string]$Description
    )
    
    $outputFile = "$hostDir\$timestamp.$hostname.$Topic.txt"
    Write-Host "Processing: $Description" -ForegroundColor Yellow
    
    try {
        $result = & $ScriptBlock
        
        # Create output with header
        $output = @"
======================================================================
ACTIVE DIRECTORY INCIDENT RESPONSE - $Description
======================================================================
Generated: $(Get-Date)
Hostname: $hostname
Topic: $Topic
Status: SUCCESS
======================================================================

$($result | Out-String)

======================================================================
END OF REPORT - $Description
======================================================================
"@
        
        $output | Out-File -FilePath $outputFile -Encoding UTF8
        Write-Host "  ✓ Saved to: $(Split-Path $outputFile -Leaf)" -ForegroundColor Green
        
    } catch {
        # Write error information to file
        $errorOutput = @"
======================================================================
ACTIVE DIRECTORY INCIDENT RESPONSE - $Description
======================================================================
Generated: $(Get-Date)
Hostname: $hostname  
Topic: $Topic
Status: ERROR
======================================================================

ERROR OCCURRED DURING EXECUTION:

Error Message: $($_.Exception.Message)
Error Line: $($_.InvocationInfo.ScriptLineNumber)
Error Position: $($_.InvocationInfo.OffsetInLine)
Error Command: $($_.InvocationInfo.Line.Trim())

Full Error Details:
$($_ | Out-String)

======================================================================
END OF ERROR REPORT - $Description  
======================================================================
"@
        
        $errorOutput | Out-File -FilePath $outputFile -Encoding UTF8
        Write-Host "  ✗ Error occurred - details saved to: $(Split-Path $outputFile -Leaf)" -ForegroundColor Red
    }
}

# 1. DCSYNC ATTACK DETECTION
Write-IROutput -Topic "DCSync-Permissions" -Description "DCSync Attack Detection - Permissions Analysis" -ScriptBlock {
    Write-Output "=== CHECKING FOR DCSYNC PERMISSIONS ==="
    Write-Output ""
    
    Write-Output "--- Privileged Users with AdminCount = 1 ---"
    Get-ADUser -Filter * -Properties whenCreated,whenChanged,lastLogon,lastLogonTimestamp,adminCount,servicePrincipalName | 
        Where-Object {$_.adminCount -eq 1} | 
        Select-Object Name,SamAccountName,whenCreated,whenChanged,@{N='LastLogon';E={if($_.lastLogon){[DateTime]::FromFileTime($_.lastLogon)}else{"Never"}}},adminCount |
        Format-Table -AutoSize
    
    Write-Output "--- DCSync Rights on Domain Root ---"
    $domainRoot = (Get-ADRootDSE).defaultNamingContext
    Write-Output "Domain Root DN: $domainRoot"
    Write-Output ""
    
    # Using dsacls for replication permissions
    Write-Output "--- DSACLS Output for Replication Rights ---"
    $dsaclsOutput = dsacls $domainRoot 2>&1 | Where-Object {$_ -match "replicate|Replicating Directory Changes"}
    if ($dsaclsOutput) {
        $dsaclsOutput
    } else {
        Write-Output "No explicit replication rights found in dsacls output"
    }
}

Write-IROutput -Topic "DCSync-EventLogs" -Description "DCSync Attack Detection - Event Log Analysis" -ScriptBlock {
    Write-Output "=== DCSYNC EVENT LOG ANALYSIS ==="
    Write-Output ""
    
    Write-Output "--- Directory Service Replication Events (Event ID 4662) ---"
    $replEvents = Get-WinEvent -FilterHashtable @{LogName='Directory Service';ID=4662} -MaxEvents 1000 -ErrorAction SilentlyContinue | 
        Where-Object {$_.Message -like "*Replicating Directory Changes*"} |
        Select-Object TimeCreated,Id,LevelDisplayName,@{N='User';E={($_.Message -split '\n' | Select-String 'Subject:' -Context 0,3)[0].Context.PostContext[2] -replace '\s+Account Name:\s+'}},@{N='ObjectAccessed';E={($_.Message -split '\n' | Select-String 'Object:' -Context 0,2)[0].Context.PostContext[1] -replace '\s+Object Name:\s+'}} |
        Sort-Object TimeCreated -Descending
    
    if ($replEvents) {
        $replEvents | Format-Table -AutoSize -Wrap
        Write-Output ""
        Write-Output "Total replication events found: $($replEvents.Count)"
    } else {
        Write-Output "No suspicious replication events found in Directory Service log"
    }
}

# 2. GOLDEN TICKET DETECTION
Write-IROutput -Topic "GoldenTicket-Analysis" -Description "Golden Ticket Detection Analysis" -ScriptBlock {
    Write-Output "=== GOLDEN TICKET DETECTION ==="
    Write-Output ""
    
    Write-Output "--- KRBTGT Account Analysis ---"
    $krbtgt = Get-ADUser krbtgt -Properties PasswordLastSet,PasswordNeverExpires,whenCreated,whenChanged,lastLogon |
        Select-Object Name,PasswordLastSet,PasswordNeverExpires,whenCreated,whenChanged,
        @{N='PasswordAgeDays';E={if($_.PasswordLastSet){((Get-Date) - $_.PasswordLastSet).Days}else{"Never Set"}}},
        @{N='LastLogon';E={if($_.lastLogon){[DateTime]::FromFileTime($_.lastLogon)}else{"Never"}}}
    
    $krbtgt | Format-List
    
    Write-Output "--- Multiple KRBTGT Account Check ---"
    $allKrbtgt = Get-ADUser -Filter {Name -like "krbtgt*"} -Properties whenCreated,whenChanged,PasswordLastSet
    $allKrbtgt | Select-Object Name,SamAccountName,whenCreated,whenChanged,PasswordLastSet | Format-Table -AutoSize
    Write-Output "Total KRBTGT-like accounts found: $($allKrbtgt.Count)"
    if ($allKrbtgt.Count -gt 1) {
        Write-Output "WARNING: Multiple KRBTGT accounts detected - this may indicate compromise!"
    }
    
    Write-Output "--- Recent Kerberos TGT Events (Event ID 4768) ---"
    $tgtEvents = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4768} -MaxEvents 1000 -ErrorAction SilentlyContinue |
        ForEach-Object {
            $msg = $_.Message
            [PSCustomObject]@{
                Time = $_.TimeCreated
                AccountName = if($msg -match 'Account Name:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
                ClientAddress = if($msg -match 'Client Address:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
                EncryptionType = if($msg -match 'Ticket Encryption Type:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
                Result = if($msg -match 'Result Code:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
            }
        } | Where-Object {$_.AccountName -ne "ANONYMOUS LOGON" -and $_.AccountName -notmatch '\$$'} |
        Sort-Object Time -Descending |
        Select-Object -First 50
    
    if ($tgtEvents) {
        $tgtEvents | Format-Table -AutoSize
    } else {
        Write-Output "No recent TGT events found"
    }
}

# 3. SILVER TICKET DETECTION  
Write-IROutput -Topic "SilverTicket-ServiceAccounts" -Description "Silver Ticket Detection - Service Account Analysis" -ScriptBlock {
    Write-Output "=== SILVER TICKET DETECTION - SERVICE ACCOUNTS ==="
    Write-Output ""
    
    Write-Output "--- Service Accounts with SPNs ---"
    $serviceAccounts = Get-ADUser -Filter {servicePrincipalName -like "*"} -Properties servicePrincipalName,PasswordLastSet,lastLogon,whenChanged |
        Select-Object Name,SamAccountName,
        @{N='SPNs';E={$_.servicePrincipalName -join '; '}},
        PasswordLastSet,
        @{N='LastLogon';E={if($_.lastLogon){[DateTime]::FromFileTime($_.lastLogon)}else{"Never"}}},
        whenChanged,
        @{N='PasswordAge';E={if($_.PasswordLastSet){((Get-Date) - $_.PasswordLastSet).Days}else{"Unknown"}}}
    
    $serviceAccounts | Format-Table -AutoSize -Wrap
    Write-Output "Total service accounts found: $($serviceAccounts.Count)"
    
    Write-Output "--- Service Accounts with Old Passwords (>90 days) ---"
    $oldPasswordAccounts = $serviceAccounts | Where-Object {$_.PasswordAge -is [int] -and $_.PasswordAge -gt 90}
    if ($oldPasswordAccounts) {
        $oldPasswordAccounts | Format-Table -AutoSize -Wrap
    } else {
        Write-Output "No service accounts with passwords older than 90 days found"
    }
}

Write-IROutput -Topic "SilverTicket-ServiceTickets" -Description "Silver Ticket Detection - Service Ticket Analysis" -ScriptBlock {
    Write-Output "=== SILVER TICKET DETECTION - SERVICE TICKETS ==="
    Write-Output ""
    
    Write-Output "--- Service Ticket Requests (Event ID 4769) ---"
    $serviceTickets = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4769} -MaxEvents 2000 -ErrorAction SilentlyContinue |
        ForEach-Object {
            $msg = $_.Message
            [PSCustomObject]@{
                Time = $_.TimeCreated
                ServiceName = if($msg -match 'Service Name:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
                AccountName = if($msg -match 'Account Name:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
                ClientAddress = if($msg -match 'Client Address:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
                TicketEncryption = if($msg -match 'Ticket Encryption Type:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
                Result = if($msg -match 'Failure Code:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
            }
        } | Where-Object {$_.AccountName -notmatch '\$$' -and $_.Result -eq "0x0"}
    
    if ($serviceTickets) {
        Write-Output "--- Top Service Ticket Requests by Service ---"
        $serviceTickets | Group-Object ServiceName | Sort-Object Count -Descending | 
            Select-Object Name,Count | Format-Table -AutoSize
        
        Write-Output "--- Top Service Ticket Requests by Account ---"  
        $serviceTickets | Group-Object AccountName | Sort-Object Count -Descending |
            Select-Object Name,Count | Select-Object -First 20 | Format-Table -AutoSize
            
        Write-Output "--- Recent Service Ticket Details ---"
        $serviceTickets | Sort-Object Time -Descending | Select-Object -First 25 | Format-Table -AutoSize
    } else {
        Write-Output "No service ticket events found"
    }
}

# 4. VULNERABLE SERVICE ACCOUNTS
Write-IROutput -Topic "VulnerableAccounts-Analysis" -Description "Vulnerable Service Accounts Analysis" -ScriptBlock {
    Write-Output "=== VULNERABLE SERVICE ACCOUNTS ANALYSIS ==="
    Write-Output ""
    
    Write-Output "--- Service Accounts with Security Issues ---"
    $vulnAccounts = Get-ADUser -Filter {servicePrincipalName -like "*"} -Properties servicePrincipalName,PasswordLastSet,PasswordNeverExpires,adminCount,memberOf,"msDS-SupportedEncryptionTypes",TrustedForDelegation,"msDS-AllowedToDelegateTo" |
        Select-Object Name,SamAccountName,
        @{N='SPNCount';E={if($_.servicePrincipalName){$_.servicePrincipalName.Count}else{0}}},
        PasswordLastSet,
        @{N='PasswordAge';E={if($_.PasswordLastSet){((Get-Date) - $_.PasswordLastSet).Days}else{"Never Set"}}},
        PasswordNeverExpires,
        adminCount,
        @{N='IsPrivileged';E={$_.adminCount -eq 1 -or $_.memberOf -match "Domain Admins|Enterprise Admins|Schema Admins"}},
        @{N='EncryptionTypes';E={$_."msDS-SupportedEncryptionTypes"}},
        @{N='HasRC4Only';E={
            $encTypes = $_."msDS-SupportedEncryptionTypes"
            if($encTypes) {
                ($encTypes -band 4) -and !(($encTypes -band 16) -or ($encTypes -band 8))
            } else { $false }
        }},
        TrustedForDelegation,
        @{N='ConstrainedDelegation';E={$_."msDS-AllowedToDelegateTo" -ne $null}}
    
    $vulnAccounts | Format-Table -AutoSize -Wrap
    
    Write-Output "--- HIGH RISK SERVICE ACCOUNTS ---"
    $highRisk = $vulnAccounts | Where-Object {
        $_.PasswordAge -eq "Never Set" -or 
        ($_.PasswordAge -is [int] -and $_.PasswordAge -gt 90) -or
        $_.PasswordNeverExpires -eq $true -or
        $_.IsPrivileged -eq $true -or
        $_.HasRC4Only -eq $true -or
        $_.TrustedForDelegation -eq $true -or
        $_.ConstrainedDelegation -eq $true
    }
    
    if ($highRisk) {
        $highRisk | Format-Table -AutoSize -Wrap
        Write-Output "HIGH RISK ACCOUNTS FOUND: $($highRisk.Count)"
    } else {
        Write-Output "No high-risk service accounts identified"
    }
    
    Write-Output "--- Unconstrained Delegation Accounts ---"
    $unconstrainedDel = Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation,servicePrincipalName,adminCount
    if ($unconstrainedDel) {
        $unconstrainedDel | Select-Object Name,SamAccountName,TrustedForDelegation,adminCount | Format-Table -AutoSize
    } else {
        Write-Output "No unconstrained delegation accounts found"
    }
    
    Write-Output "--- Constrained Delegation Accounts ---"
    $constrainedDel = Get-ADUser -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties "msDS-AllowedToDelegateTo",servicePrincipalName
    if ($constrainedDel) {
        $constrainedDel | Select-Object Name,SamAccountName,@{N='DelegationTargets';E={$_."msDS-AllowedToDelegateTo" -join '; '}} | Format-Table -AutoSize -Wrap
    } else {
        Write-Output "No constrained delegation accounts found"
    }
}

# 5. CREDENTIAL DUMPING DETECTION
Write-IROutput -Topic "CredentialDumping-FileAccess" -Description "Credential Dumping Detection - File Access Analysis" -ScriptBlock {
    Write-Output "=== CREDENTIAL DUMPING DETECTION - FILE ACCESS ==="
    Write-Output ""
    
    Write-Output "--- NTDS.DIT File Access Events (Event ID 4663) ---"
    $ntdsAccess = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4663} -MaxEvents 1000 -ErrorAction SilentlyContinue |
        Where-Object {$_.Message -like "*ntds.dit*"} |
        ForEach-Object {
            $msg = $_.Message
            [PSCustomObject]@{
                Time = $_.TimeCreated
                ProcessName = if($msg -match 'Process Name:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
                SubjectUser = if($msg -match 'Subject:.*?Account Name:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
                ObjectName = if($msg -match 'Object Name:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
                AccessMask = if($msg -match 'Access Mask:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
            }
        } | Sort-Object Time -Descending
    
    if ($ntdsAccess) {
        $ntdsAccess | Format-Table -AutoSize -Wrap
        Write-Output "NTDS.DIT access events found: $($ntdsAccess.Count)"
    } else {
        Write-Output "No NTDS.DIT file access events found"
    }
    
    Write-Output "--- Volume Shadow Copy Events ---"
    $vssEvents = Get-WinEvent -FilterHashtable @{LogName='System';ID=7036,7040} -MaxEvents 500 -ErrorAction SilentlyContinue |
        Where-Object {$_.Message -like "*Volume Shadow Copy*"} |
        Select-Object TimeCreated,Id,LevelDisplayName,Message |
        Sort-Object TimeCreated -Descending
    
    if ($vssEvents) {
        $vssEvents | Format-Table -AutoSize -Wrap
    } else {
        Write-Output "No Volume Shadow Copy events found"
    }
    
    Write-Output "--- ESENT Database Events (NTDS.DIT related) ---"
    $esentEvents = Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName='ESENT'} -MaxEvents 500 -ErrorAction SilentlyContinue |
        Where-Object {$_.Message -like "*ntds.dit*"} |
        Select-Object TimeCreated,Id,LevelDisplayName,Message |
        Sort-Object TimeCreated -Descending
    
    if ($esentEvents) {
        $esentEvents | Format-Table -AutoSize -Wrap
    } else {
        Write-Output "No ESENT events related to NTDS.DIT found"
    }
}

Write-IROutput -Topic "CredentialDumping-ProcessAccess" -Description "Credential Dumping Detection - Process Access Analysis" -ScriptBlock {
    Write-Output "=== CREDENTIAL DUMPING - PROCESS ACCESS ==="
    Write-Output ""
    
    Write-Output "--- LSASS Process Access Events (Event ID 4656) ---"
    $lsassAccess = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4656} -MaxEvents 1000 -ErrorAction SilentlyContinue |
        Where-Object {$_.Message -like "*lsass.exe*"} |
        ForEach-Object {
            $msg = $_.Message
            [PSCustomObject]@{
                Time = $_.TimeCreated
                ProcessName = if($msg -match 'Process Name:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
                SubjectUser = if($msg -match 'Subject:.*?Account Name:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
                ObjectName = if($msg -match 'Object Name:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
                AccessMask = if($msg -match 'Access Mask:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
            }
        } | Sort-Object Time -Descending
    
    if ($lsassAccess) {
        $lsassAccess | Select-Object -First 25 | Format-Table -AutoSize -Wrap
        Write-Output "LSASS access events found: $($lsassAccess.Count)"
    } else {
        Write-Output "No LSASS process access events found"
    }
    
    Write-Output "--- Suspicious Process Creation Events (Event ID 4688) ---"
    $suspiciousProcs = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} -MaxEvents 1000 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Message -like "*ntdsutil*" -or 
            $_.Message -like "*vssadmin*" -or
            $_.Message -like "*wbadmin*" -or
            ($_.Message -like "*powershell*" -and $_.Message -like "*ntds*") -or
            $_.Message -like "*mimikatz*" -or
            $_.Message -like "*sekurlsa*"
        } | ForEach-Object {
            $msg = $_.Message
            [PSCustomObject]@{
                Time = $_.TimeCreated
                ProcessName = if($msg -match 'New Process Name:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
                CommandLine = if($msg -match 'Process Command Line:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Not Available"}
                SubjectUser = if($msg -match 'Subject:.*?Account Name:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
                ParentProcess = if($msg -match 'Creator Process Name:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
            }
        } | Sort-Object Time -Descending
    
    if ($suspiciousProcs) {
        $suspiciousProcs | Format-Table -AutoSize -Wrap
        Write-Output "Suspicious process events found: $($suspiciousProcs.Count)"
    } else {
        Write-Output "No suspicious process creation events found"
    }
}

# 6. DANGEROUS AD ACLS
Write-IROutput -Topic "DangerousACLs-Analysis" -Description "Dangerous Active Directory ACLs Analysis" -ScriptBlock {
    Write-Output "=== DANGEROUS AD ACLS ANALYSIS ==="
    Write-Output ""
    
    $domainDN = (Get-ADRootDSE).defaultNamingContext
    $configDN = (Get-ADRootDSE).configurationNamingContext
    
    Write-Output "Domain DN: $domainDN"
    Write-Output "Config DN: $configDN"
    Write-Output ""
    
    Write-Output "--- AdminSDHolder Permissions ---"
    $adminSDHolder = "CN=AdminSDHolder,CN=System,$domainDN"
    Write-Output "Checking: $adminSDHolder"
    $adminSDHolderACL = dsacls $adminSDHolder 2>&1
    $adminSDHolderACL | Where-Object {$_ -notmatch "Successfully completed command|The command completed successfully"}
    
    Write-Output ""
    Write-Output "--- Domain Root Permissions ---"
    $domainRootACL = dsacls $domainDN 2>&1 | Where-Object {$_ -match "FULL CONTROL|Generic all|Write|Create|Delete" -and $_ -notmatch "NT AUTHORITY\\SYSTEM|BUILTIN\\Administrators|Domain Admins"}
    if ($domainRootACL) {
        $domainRootACL
    } else {
        Write-Output "No unusual permissions found on domain root"
    }
    
    Write-Output ""
    Write-Output "--- Privileged Group Permissions ---"
    $privGroups = @("Domain Admins","Enterprise Admins","Schema Admins","Administrators","Account Operators","Backup Operators")
    foreach($group in $privGroups) {
        Write-Output "--- Checking $group ---"
        try {
            $groupDN = (Get-ADGroup $group -ErrorAction Stop).DistinguishedName
            $groupACL = dsacls $groupDN 2>&1 | Where-Object {$_ -match "Allow" -and $_ -notmatch "NT AUTHORITY\\SYSTEM|BUILTIN\\Administrators|$group"}
            if ($groupACL) {
                $groupACL
            } else {
                Write-Output "  Standard permissions found"
            }
        } catch {
            Write-Output "  Could not check $group : $($_.Exception.Message)"
        }
        Write-Output ""
    }
    
    Write-Output "--- Users with Replication Rights ---"
    $replicationRights = dsacls $domainDN 2>&1 | Where-Object {$_ -match "Replicate|REPLICATING DIRECTORY CHANGES"}
    if ($replicationRights) {
        Write-Output "POTENTIAL DCSYNC PERMISSIONS FOUND:"
        $replicationRights
    } else {
        Write-Output "No unusual replication rights found"
    }
}

# 7. HIDDEN OBJECTS IN AD
Write-IROutput -Topic "HiddenObjects-Analysis" -Description "Hidden Active Directory Objects Analysis" -ScriptBlock {
    Write-Output "=== HIDDEN AD OBJECTS ANALYSIS ==="
    Write-Output ""
    
    Write-Output "--- Users Hidden in Advanced View ---"
    $hiddenUsers = Get-ADUser -Filter * -Properties ShowInAdvancedViewOnly |
        Where-Object {$_.ShowInAdvancedViewOnly -eq $true} |
        Select-Object Name,SamAccountName,DistinguishedName,ShowInAdvancedViewOnly
    
    if ($hiddenUsers) {
        $hiddenUsers | Format-Table -AutoSize -Wrap
    } else {
        Write-Output "No users marked as hidden in advanced view"
    }
    
    Write-Output "--- Users with Suspicious Descriptions ---"
    $suspiciousDesc = Get-ADUser -Filter * -Properties Description,Info,Comment |
        Where-Object {
            ($_.Description -and ($_.Description -match "password|pwd|temp|test|admin|svc")) -or
            ($_.Info -and ($_.Info -match "password|pwd|temp|test|admin|svc")) -or
            ($_.Comment -and ($_.Comment -match "password|pwd|temp|test|admin|svc"))
        } | Select-Object Name,SamAccountName,Description,Info,Comment
    
    if ($suspiciousDesc) {
        $suspiciousDesc | Format-Table -AutoSize -Wrap
    } else {
        Write-Output "No users with suspicious descriptions found"
    }
    
    Write-Output "--- Recently Created Privileged Accounts (30 days) ---"
    $recentPriv = Get-ADUser -Filter * -Properties whenCreated,adminCount,memberOf |
        Where-Object {
            $_.whenCreated -gt (Get-Date).AddDays(-30) -and (
                $_.adminCount -eq 1 -or
                ($_.memberOf -and ($_.memberOf -match "Domain Admins|Enterprise Admins|Schema Admins"))
            )
        } | Select-Object Name,SamAccountName,whenCreated,adminCount,@{N='PrivilegedGroups';E={($_.memberOf | Where-Object {$_ -match "Domain Admins|Enterprise Admins|Schema Admins"}) -join '; '}}
    
    if ($recentPriv) {
        $recentPriv | Format-Table -AutoSize -Wrap
        Write-Output "ALERT: Recently created privileged accounts found!"
    } else {
        Write-Output "No recently created privileged accounts found"
    }
    
    Write-Output "--- Accounts with Unusual Naming Patterns ---"
    $unusualNaming = Get-ADUser -Filter * |
        Where-Object {
            $_.Name -match "^\$|^~|^_|^\.|\$\$" -or  # Special characters
            ($_.SamAccountName -match "admin|svc|service|backup|test" -and $_.Name -notmatch "admin|svc|service|backup|test")  # Mismatched naming
        } | Select-Object Name,SamAccountName,DistinguishedName
    
    if ($unusualNaming) {
        $unusualNaming | Format-Table -AutoSize -Wrap
    } else {
        Write-Output "No accounts with unusual naming patterns found"
    }
    
    Write-Output "--- Recently Modified Disabled Accounts (7 days) ---"
    $recentDisabled = Get-ADUser -Filter {Enabled -eq $false} -Properties whenChanged |
        Where-Object {$_.whenChanged -gt (Get-Date).AddDays(-7)} |
        Select-Object Name,SamAccountName,Enabled,whenChanged
    
    if ($recentDisabled) {
        $recentDisabled | Format-Table -AutoSize
        Write-Output "Recently modified disabled accounts may indicate cleanup activity"
    } else {
        Write-Output "No recently modified disabled accounts found"
    }
    
    Write-Output "--- Accounts in Unusual OUs ---"
    $unusualOUs = Get-ADUser -Filter * -Properties CanonicalName |
        Where-Object {
            $_.CanonicalName -notmatch "Users|People|Accounts|Staff|Employees|Domain Users|Service Accounts|System|Exchange|Microsoft Exchange" -and
            $_.CanonicalName -match "/" # Has OU structure
        } | Select-Object Name,SamAccountName,CanonicalName
    
    if ($unusualOUs) {
        $unusualOUs | Select-Object -First 20 | Format-Table -AutoSize -Wrap
    } else {
        Write-Output "No accounts in unusual OUs found"
    }
}

# 8. KERBEROASTING DETECTION
Write-IROutput -Topic "Kerberoasting-Analysis" -Description "Kerberoasting Attack Detection" -ScriptBlock {
    Write-Output "=== KERBEROASTING DETECTION ==="
    Write-Output ""
    
    Write-Output "--- Service Ticket Requests with RC4 Encryption (Event 4769) ---"
    $kerberoastingEvents = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4769} -MaxEvents 2000 -ErrorAction SilentlyContinue |
        Where-Object {$_.Message -match "Ticket Encryption Type:\s+0x17"} |  # RC4
        ForEach-Object {
            $msg = $_.Message
            [PSCustomObject]@{
                Time = $_.TimeCreated
                ServiceName = if($msg -match 'Service Name:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
                AccountName = if($msg -match 'Account Name:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
                ClientAddress = if($msg -match 'Client Address:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
                Result = if($msg -match 'Failure Code:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
            }
        } | Where-Object {$_.AccountName -notmatch '\$' -and $_.Result -eq "0x0"} |
        Sort-Object Time -Descending
    
    if ($kerberoastingEvents) {
        Write-Output "--- Potential Kerberoasting Activity Summary ---"
        $kerberoastingEvents | Group-Object AccountName | Sort-Object Count -Descending | 
            Select-Object Name,Count | Format-Table -AutoSize
        
        Write-Output "--- Targeted Services ---"
        $kerberoastingEvents | Group-Object ServiceName | Sort-Object Count -Descending |
            Select-Object Name,Count | Format-Table -AutoSize
        
        Write-Output "--- Recent RC4 Service Ticket Requests ---"
        $kerberoastingEvents | Select-Object -First 25 | Format-Table -AutoSize -Wrap
        
        Write-Output "ALERT: Potential Kerberoasting activity detected - $($kerberoastingEvents.Count) RC4 service ticket requests found!"
    } else {
        Write-Output "No RC4 service ticket requests found (good sign)"
    }
    
    Write-Output "--- ASREPRoasting Check ---"
    $asrepUsers = Get-ADUser -Filter * -Properties DoesNotRequirePreAuth |
        Where-Object {$_.DoesNotRequirePreAuth -eq $true} |
        Select-Object Name,SamAccountName,DoesNotRequirePreAuth,DistinguishedName
    
    if ($asrepUsers) {
        $asrepUsers | Format-Table -AutoSize -Wrap
        Write-Output "ALERT: Users with 'Do not require Kerberos preauthentication' found - vulnerable to ASREPRoasting!"
    } else {
        Write-Output "No users vulnerable to ASREPRoasting found"
    }
}

# 9. SUSPICIOUS DOMAIN CONTROLLER DETECTION
Write-IROutput -Topic "RogueDC-Detection" -Description "Rogue Domain Controller Detection" -ScriptBlock {
    Write-Output "=== ROGUE DOMAIN CONTROLLER DETECTION ==="
    Write-Output ""
    
    Write-Output "--- All Domain Controllers ---"
    $allDCs = Get-ADDomainController -Filter * |
        Select-Object Name,Site,OperatingSystem,OperatingSystemVersion,IPv4Address,IsGlobalCatalog,IsReadOnly
    $allDCs | Format-Table -AutoSize
    Write-Output "Total Domain Controllers: $($allDCs.Count)"
    
    Write-Output "--- Computers with LDAP SPNs (Potential Rogue DCs) ---"
    $ldapComputers = Get-ADComputer -Filter * -Properties OperatingSystem,servicePrincipalName,whenCreated |
        Where-Object {$_.servicePrincipalName -like "*ldap*"} |
        Select-Object Name,OperatingSystem,whenCreated,
        @{N='LDAPSPNs';E={($_.servicePrincipalName | Where-Object {$_ -like "*ldap*"}) -join '; '}}
    
    if ($ldapComputers) {
        $ldapComputers | Format-Table -AutoSize -Wrap
        
        # Check for non-server systems with LDAP SPNs
        $suspiciousLDAP = $ldapComputers | Where-Object {$_.OperatingSystem -notlike "*Server*"}
        if ($suspiciousLDAP) {
            Write-Output "ALERT: Non-server systems with LDAP SPNs found - potential rogue DCs!"
            $suspiciousLDAP | Format-Table -AutoSize -Wrap
        }
    } else {
        Write-Output "No computers with LDAP SPNs found outside of expected DCs"
    }
    
    Write-Output "--- Recent Computer Account Creations (30 days) ---"
    $recentComputers = Get-ADComputer -Filter * -Properties whenCreated,OperatingSystem |
        Where-Object {$_.whenCreated -gt (Get-Date).AddDays(-30)} |
        Sort-Object whenCreated -Descending |
        Select-Object Name,OperatingSystem,whenCreated
    
    if ($recentComputers) {
        $recentComputers | Format-Table -AutoSize
        Write-Output "Monitor these recent computer accounts for suspicious activity"
    } else {
        Write-Output "No computers created in the last 30 days"
    }
    
    Write-Output "--- Directory Service Event Log Analysis ---"
    $dsEvents = Get-WinEvent -FilterHashtable @{LogName='Directory Service'} -MaxEvents 100 -ErrorAction SilentlyContinue |
        Where-Object {$_.LevelDisplayName -eq "Warning" -or $_.LevelDisplayName -eq "Error"} |
        Select-Object TimeCreated,Id,LevelDisplayName,Message |
        Sort-Object TimeCreated -Descending
    
    if ($dsEvents) {
        $dsEvents | Select-Object -First 10 | Format-Table -AutoSize -Wrap
    } else {
        Write-Output "No recent Directory Service warnings or errors found"
    }
}

# 10. AUTHENTICATION ANOMALIES
Write-IROutput -Topic "AuthAnomalies-Analysis" -Description "Authentication Anomalies Analysis" -ScriptBlock {
    Write-Output "=== AUTHENTICATION ANOMALIES ANALYSIS ==="
    Write-Output ""
    
    Write-Output "--- Suspicious Logon Events (Event ID 4624) ---"
    $suspiciousLogons = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -MaxEvents 1000 -ErrorAction SilentlyContinue |
        Where-Object {
            ($_.Message -like "*Logon Type:*3*" -or $_.Message -like "*Logon Type:*10*") -and
            $_.Message -notlike "*ANONYMOUS LOGON*"
        } | ForEach-Object {
            $msg = $_.Message
            [PSCustomObject]@{
                Time = $_.TimeCreated
                LogonType = if($msg -match 'Logon Type:\s+(\d+)') {$matches[1]} else {"Unknown"}
                Account = if($msg -match 'Account Name:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
                Domain = if($msg -match 'Account Domain:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
                SourceIP = if($msg -match 'Source Network Address:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
                WorkstationName = if($msg -match 'Workstation Name:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
                LogonProcess = if($msg -match 'Logon Process:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
            }
        } | Where-Object {$_.Account -notmatch '\$'} |
        Sort-Object Time -Descending
    
    if ($suspiciousLogons) {
        Write-Output "--- Top Accounts by Logon Count ---"
        $suspiciousLogons | Group-Object Account | Sort-Object Count -Descending |
            Select-Object Name,Count | Select-Object -First 15 | Format-Table -AutoSize
        
        Write-Output "--- Top Source IPs ---"
        $suspiciousLogons | Where-Object {$_.SourceIP -ne "-" -and $_.SourceIP -ne "Unknown"} |
            Group-Object SourceIP | Sort-Object Count -Descending |
            Select-Object Name,Count | Select-Object -First 10 | Format-Table -AutoSize
        
        Write-Output "--- Recent Logon Details ---"
        $suspiciousLogons | Select-Object -First 20 | Format-Table -AutoSize -Wrap
    } else {
        Write-Output "No suspicious network logons found"
    }
    
    Write-Output "--- Failed Logon Attempts (Event ID 4625) ---"
    $failedLogons = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 500 -ErrorAction SilentlyContinue |
        ForEach-Object {
            $msg = $_.Message
            [PSCustomObject]@{
                Time = $_.TimeCreated
                Account = if($msg -match 'Account Name:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
                Domain = if($msg -match 'Account Domain:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
                FailureReason = if($msg -match 'Failure Reason:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
                SourceIP = if($msg -match 'Source Network Address:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
                WorkstationName = if($msg -match 'Workstation Name:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
            }
        } | Where-Object {$_.Account -ne "ANONYMOUS LOGON" -and $_.Account -notmatch '\$'} |
        Sort-Object Time -Descending
    
    if ($failedLogons) {
        Write-Output "--- Top Failed Accounts ---"
        $failedLogons | Group-Object Account | Sort-Object Count -Descending |
            Select-Object Name,Count | Select-Object -First 10 | Format-Table -AutoSize
        
        Write-Output "--- Failure Reasons ---"
        $failedLogons | Group-Object FailureReason | Sort-Object Count -Descending |
            Select-Object Name,Count | Format-Table -AutoSize
        
        Write-Output "--- Recent Failed Logons ---"
        $failedLogons | Select-Object -First 15 | Format-Table -AutoSize -Wrap
    } else {
        Write-Output "No recent failed logon attempts found"
    }
    
    Write-Output "--- Privilege Use Events (Event ID 4672) ---"
    $privUse = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4672} -MaxEvents 200 -ErrorAction SilentlyContinue |
        ForEach-Object {
            $msg = $_.Message
            [PSCustomObject]@{
                Time = $_.TimeCreated
                Account = if($msg -match 'Account Name:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
                Domain = if($msg -match 'Account Domain:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
                LogonId = if($msg -match 'Logon ID:\s+([^\r\n]+)') {$matches[1].Trim()} else {"Unknown"}
            }
        } | Where-Object {$_.Account -notmatch '\$|SYSTEM|LOCAL SERVICE|NETWORK SERVICE'} |
        Sort-Object Time -Descending
    
    if ($privUse) {
        Write-Output "--- Recent Privilege Use by Account ---"
        $privUse | Group-Object Account | Sort-Object Count -Descending |
            Select-Object Name,Count | Select-Object -First 10 | Format-Table -AutoSize
        
        Write-Output "--- Recent Privilege Use Details ---"
        $privUse | Select-Object -First 15 | Format-Table -AutoSize
    } else {
        Write-Output "No recent privilege use events found"
    }
}

# 11. FINAL SUMMARY
Write-IROutput -Topic "Summary-Report" -Description "Incident Response Summary Report" -ScriptBlock {
    Write-Output "=== ACTIVE DIRECTORY INCIDENT RESPONSE SUMMARY ==="
    Write-Output ""
    Write-Output "Scan completed: $(Get-Date)"
    Write-Output "Target system: $hostname"
    Write-Output "Domain: $((Get-ADDomain).DNSRoot)"
    Write-Output "Forest: $((Get-ADForest).Name)"
    Write-Output ""
    
    Write-Output "=== FILES GENERATED ==="
    $generatedFiles = Get-ChildItem $hostDir -Filter "$timestamp.$hostname.*.txt" | 
        Sort-Object Name |
        Select-Object Name,Length,CreationTime
    
    $generatedFiles | Format-Table -AutoSize
    Write-Output "Total files generated: $($generatedFiles.Count)"
    Write-Output "Output directory: $hostDir"
    Write-Output ""
    
    Write-Output "=== RECOMMENDED NEXT STEPS ==="
    Write-Output "1. Review all generated files for indicators of compromise"
    Write-Output "2. Correlate findings with network logs and SIEM data"  
    Write-Output "3. Check file timestamps for potential attack timeline"
    Write-Output "4. If DCSync permissions found, investigate those accounts immediately"
    Write-Output "5. If RC4 service tickets found, investigate for Kerberoasting"
    Write-Output "6. Reset KRBTGT password if Golden Ticket activity suspected"
    Write-Output "7. Review service account passwords and disable RC4 encryption"
    Write-Output "8. Implement additional monitoring for identified vulnerabilities"
    Write-Output "9. Consider running this scan on other domain controllers"
    Write-Output "10. Preserve logs and evidence for forensic analysis"
    Write-Output ""
    
    Write-Output "=== HIGH PRIORITY INDICATORS TO REVIEW ==="
    Write-Output "- Multiple KRBTGT accounts"
    Write-Output "- Recent privileged account creations"
    Write-Output "- NTDS.DIT file access events"
    Write-Output "- Replication permission assignments"  
    Write-Output "- RC4-only service accounts"
    Write-Output "- Unusual computer accounts with LDAP SPNs"
    Write-Output "- Service accounts with old passwords"
    Write-Output "- Failed authentication patterns"
    Write-Output "- Hidden or suspicious user accounts"
    Write-Output "- Volume Shadow Copy operations"
    Write-Output ""
    
    Write-Output "Report generated by AD Incident Response Script v1.0"
    Write-Output "For questions or additional analysis, review individual topic files"
}

# Script completion message
Write-Host ""
Write-Host "=" * 60 -ForegroundColor Green
Write-Host "AD INCIDENT RESPONSE SCAN COMPLETED" -ForegroundColor Green  
Write-Host "=" * 60 -ForegroundColor Green
Write-Host "All output files have been saved to: $hostDir" -ForegroundColor Cyan
Write-Host "Files are named with timestamp: $timestamp" -ForegroundColor Cyan
Write-Host ""
Write-Host "Review the Summary-Report file first for an overview of findings." -ForegroundColor Yellow
Write-Host "Then examine individual topic files for detailed analysis." -ForegroundColor Yellow
Write-Host ""
Write-Host "IMPORTANT: Preserve these files as evidence and correlate with other logs!" -ForegroundColor Red
