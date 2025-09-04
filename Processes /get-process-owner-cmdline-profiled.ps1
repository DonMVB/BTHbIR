
$startTime = Get-Date

Get-CimInstance Win32_Process | ForEach-Object {
try {
   $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction stop
   $user = if ($owner.ReturnValue -eq 0) { 
      "$($owner.Domain)\$($owner.User)" 
   } else { 
      "N/A" 
   }
} catch {
     $user = "Error."
}
    [PSCustomObject]@{
        ProcessName = $_.Name
        User        = $user
        CommandLine = $_.CommandLine
    }
} | Format-Table -AutoSize

$endTime = Get-Date
$duration = $endTime - $startTime
Write-Host "Execution Time: $($duration.Minutes) minute(s) and $($duration.Seconds) second(s)"

