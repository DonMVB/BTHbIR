# Global configuration
$HourLimit = 24  # Set to 0 to pull all data, or specify hours to limit results

# Calculate the cutoff time if HourLimit is set
$CutoffTime = if ($HourLimit -gt 0) {
    (Get-Date).AddHours(-$HourLimit)
} else {
    $null
}

# Initialize variables to track earliest and latest times
$EarliestTime = $null
$LatestTime = $null

$Hash = @{}

# Build the filter hashtable
$FilterHashtable = @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    ID = 1
}

# Add time filter if HourLimit is specified
if ($CutoffTime) {
    $FilterHashtable['StartTime'] = $CutoffTime
}

$entries = Get-WinEvent -FilterHashtable $FilterHashtable | 
    ForEach-Object {
        # Track the earliest and latest event times
        $EventTime = $_.TimeCreated
        
        if ($EarliestTime -eq $null -or $EventTime -lt $EarliestTime) {
            $EarliestTime = $EventTime
        }
        
        if ($LatestTime -eq $null -or $EventTime -gt $LatestTime) {
            $LatestTime = $EventTime
        }
        
        # Extract the Image path from the event
        $xml = [xml]$_.ToXml()
        ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'}).'#text'
    }

# Count occurrences of each executable
foreach ($l in $entries) {
    if ($Hash[$l] -eq $null) {
        $Hash[$l] = 1
    } else {
        $Hash[$l]++
    }
}

# Output the results sorted by frequency
$Hash.GetEnumerator() | Sort-Object -Descending -Property Value | ForEach-Object {
    $msg = '{0} {1}' -f $_.Value, $_.Key
    Write-Output $msg
}

# Report the time range of processed events
Write-Output ""
Write-Output "=== Event Time Range Summary ==="
if ($EarliestTime -and $LatestTime) {
    Write-Output "Earliest event time: $($EarliestTime.ToString('yyyy-MM-dd HH:mm:ss'))"
    Write-Output "Latest event time:   $($LatestTime.ToString('yyyy-MM-dd HH:mm:ss'))"
    $TimeSpan = $LatestTime - $EarliestTime
    Write-Output "Time span covered:   $([math]::Round($TimeSpan.TotalHours, 2)) hours"
} else {
    Write-Output "No events were processed."
}

if ($HourLimit -gt 0) {
    Write-Output "Filter applied:      Last $HourLimit hours (since $($CutoffTime.ToString('yyyy-MM-dd HH:mm:ss')))"
} else {
    Write-Output "Filter applied:      All available events"
}
