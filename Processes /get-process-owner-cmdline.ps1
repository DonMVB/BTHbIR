$CmdLines = @{}
Get-CimInstance Win32_Process | ForEach-Object { $CmdLines[$_.Handle] = $_.CommandLine }

# Get owners via WMI (more reliable for this specific operation)
$Owners = @{}
Get-WmiObject Win32_Process | ForEach-Object { 
    $owner = try { $_.GetOwner().User } catch { "System" }
    $Owners[$_.Handle] = $owner 
}

Get-Process | Select-Object Id, ProcessName,
    @{Name="Owner"; Expression={$Owners[$_.Id.ToString()]}},
    @{Name="CommandLine"; Expression={$CmdLines[$_.Id.ToString()]}}
