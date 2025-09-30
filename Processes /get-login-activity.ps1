# Extract Windows Security Events for Logon, Authentication, and Access Monitoring
# Comprehensive collection of security events for logon tracking

# Logon Type mapping
$LogonTypes = @{
    2  = "Interactive"
    3  = "Network"
    4  = "Batch"
    5  = "Service"
    7  = "Unlock"
    8  = "NetworkCleartext"
    9  = "NewCredentials"
    10 = "RemoteInteractive"
    11 = "CachedInteractive"
}

# Event ID descriptions
$EventDescriptions = @{
    4624 = "Successful Logon"
    4625 = "Failed Logon"
    4634 = "Logoff"
    4647 = "User Initiated Logoff"
    4648 = "Logon with Explicit Credentials (RunAs)"
    4672 = "Special Privileges Assigned"
    4768 = "Kerberos TGT Requested"
    4769 = "Kerberos Service Ticket Requested"
    4776 = "Credential Validation (NTLM)"
    4778 = "RDP Session Reconnected"
    4779 = "RDP Session Disconnected"
    4800 = "Workstation Locked"
    4801 = "Workstation Unlocked"
    4802 = "Screen Saver Invoked"
    4803 = "Screen Saver Dismissed"
    5140 = "Network Share Accessed"
    5145 = "Network Share Object Accessed"
}

# Define event IDs to collect
$EventIDs = 4624,4625,4634,4647,4648,4672,4768,4769,4776,4778,4779,4800,4801,4802,4803,5140,5145

# Query Security log for all event IDs
Write-Host "Querying Security log for events..." -ForegroundColor Cyan
$Events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$EventIDs} -MaxEvents 5000 -ErrorAction SilentlyContinue

if (-not $Events) {
    Write-Host "No events found or access denied. Ensure you're running as Administrator." -ForegroundColor Yellow
    exit
}

Write-Host "Processing $($Events.Count) events..." -ForegroundColor Cyan

$Results = foreach ($Event in $Events) {
    # Convert event to XML
    $XML = [xml]$Event.ToXml()
    
    # Extract data from XML using EventData structure
    $EventData = $XML.Event.EventData.Data
    
    # Create hashtable for easy lookup
    $DataHash = @{}
    foreach ($Data in $EventData) {
        $DataHash[$Data.Name] = $Data.'#text'
    }
    
    # Initialize variables
    $TargetUserName = $null
    $TargetDomainName = $null
    $WorkstationName = $null
    $IpAddress = $null
    $LogonType = $null
    $ShareName = $null
    $ObjectName = $null
    $FailureReason = $null
    $Status = $null
    $SubStatus = $null
    
    # Extract fields based on Event ID
    switch ($Event.Id) {
        {$_ -in 4624,4625,4634,4647} {
            $TargetUserName = $DataHash['TargetUserName']
            $TargetDomainName = $DataHash['TargetDomainName']
            $WorkstationName = $DataHash['WorkstationName']
            $IpAddress = $DataHash['IpAddress']
            $LogonType = $DataHash['LogonType']
            if ($_ -eq 4625) {
                $Status = $DataHash['Status']
                $SubStatus = $DataHash['SubStatus']
                $FailureReason = $DataHash['FailureReason']
            }
        }
        4648 {
            # RunAs event - shows both source and target accounts
            $TargetUserName = $DataHash['TargetUserName']
            $TargetDomainName = $DataHash['TargetDomainName']
            $WorkstationName = $DataHash['TargetServerName']
            $IpAddress = $DataHash['IpAddress']
            $LogonType = $DataHash['LogonType']
        }
        4672 {
            $TargetUserName = $DataHash['SubjectUserName']
            $TargetDomainName = $DataHash['SubjectDomainName']
            $WorkstationName = $env:COMPUTERNAME
        }
        {$_ -in 4768,4769} {
            # Kerberos events
            $TargetUserName = $DataHash['TargetUserName']
            $TargetDomainName = $DataHash['TargetDomainName']
            $IpAddress = $DataHash['IpAddress']
            $WorkstationName = $env:COMPUTERNAME
        }
        4776 {
            # NTLM authentication
            $TargetUserName = $DataHash['TargetUserName']
            $WorkstationName = $DataHash['Workstation']
        }
        {$_ -in 4778,4779} {
            # RDP session events
            $TargetUserName = $DataHash['AccountName']
            $TargetDomainName = $DataHash['AccountDomain']
            $WorkstationName = $DataHash['ClientName']
            $IpAddress = $DataHash['ClientAddress']
            $LogonType = "10"  # RDP is logon type 10
        }
        {$_ -in 4800,4801,4802,4803} {
            # Screen lock/unlock events
            $TargetUserName = $DataHash['TargetUserName']
            $TargetDomainName = $DataHash['TargetDomainName']
            $WorkstationName = $env:COMPUTERNAME
            if ($_ -in 4801,4803) {
                $LogonType = "7"  # Unlock
            }
        }
        5140 {
            # Network share accessed
            $TargetUserName = $DataHash['SubjectUserName']
            $TargetDomainName = $DataHash['SubjectDomainName']
            $WorkstationName = $DataHash['IpAddress']
            $IpAddress = $DataHash['IpAddress']
            $ShareName = $DataHash['ShareName']
            $LogonType = "3"  # Network
        }
        5145 {
            # Detailed share object access
            $TargetUserName = $DataHash['SubjectUserName']
            $TargetDomainName = $DataHash['SubjectDomainName']
            $WorkstationName = $DataHash['IpAddress']
            $IpAddress = $DataHash['IpAddress']
            $ShareName = $DataHash['ShareName']
            $ObjectName = $DataHash['RelativeTargetName']
            $LogonType = "3"  # Network
        }
    }
    
    # Build full username
    $FullUserName = if ($TargetDomainName -and $TargetUserName) {
        "$TargetDomainName\$TargetUserName"
    } elseif ($TargetUserName) {
        $TargetUserName
    } else {
        "N/A"
    }
    
    # Get logon type name
    $LogonTypeName = if ($LogonType -and $LogonTypes.ContainsKey([int]$LogonType)) {
        $LogonTypes[[int]$LogonType]
    } elseif ($LogonType) {
        "Type $LogonType"
    } else {
        "N/A"
    }
    
    # Clean up IP address
    $ClientIP = if ($IpAddress -and $IpAddress -ne '-' -and $IpAddress -ne '::1' -and $IpAddress -ne '127.0.0.1' -and $IpAddress -ne '') {
        $IpAddress
    } else {
        "N/A"
    }
    
    # Get event description
    $EventDescription = $EventDescriptions[$Event.Id]
    
    # Build additional info string
    $AdditionalInfo = @()
    if ($ShareName) { $AdditionalInfo += "Share: $ShareName" }
    if ($ObjectName) { $AdditionalInfo += "File: $ObjectName" }
    if ($FailureReason) { $AdditionalInfo += "Reason: $FailureReason" }
    if ($Status) { $AdditionalInfo += "Status: $Status" }
    $AdditionalInfoStr = if ($AdditionalInfo.Count -gt 0) { $AdditionalInfo -join " | " } else { "" }
    
    # Create output object
    [PSCustomObject]@{
        EventID        = $Event.Id
        EventType      = $EventDescription
        TimeCreated    = $Event.TimeCreated
        UserName       = $FullUserName
        SystemName     = if ($WorkstationName) { $WorkstationName } else { "N/A" }
        ClientIP       = $ClientIP
        LogonTypeCode  = if ($LogonType) { $LogonType } else { "N/A" }
        LogonTypeName  = $LogonTypeName
        AdditionalInfo = $AdditionalInfoStr
    }
}

# Display results
Write-Host "`nFound $($Results.Count) events:" -ForegroundColor Green
$Results | Sort-Object TimeCreated -Descending | Format-Table -AutoSize

# Optional: Export to CSV
# $Results | Export-Csv -Path "Security_Events_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" -NoTypeInformation
# Write-Host "Results exported to CSV" -ForegroundColor Green

# Display summary by event type
Write-Host "`nEvent Summary:" -ForegroundColor Cyan
$Results | Group-Object EventType | Select-Object Count, Name | Sort-Object Count -Descending | Format-Table -AutoSize
