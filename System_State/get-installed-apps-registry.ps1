function Get-InstalledApplications {
    param(
        [switch]$IncludeUpdates,
        [switch]$IncludeSystemComponents
    )
    
    $UninstallKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    $Applications = @()
    
    foreach ($Key in $UninstallKeys) {
        try {
            $Apps = Get-ItemProperty $Key -ErrorAction SilentlyContinue | Where-Object {
                $_.DisplayName -and
                (!$_.SystemComponent -or $IncludeSystemComponents) -and
                (!$_.ParentKeyName -or $IncludeUpdates) -and
                ($_.DisplayName -notmatch '^Update for|^Security Update for|^Hotfix for' -or $IncludeUpdates)
            }
            
            foreach ($App in $Apps) {
                $Applications += [PSCustomObject]@{
                    'DisplayName' = $App.DisplayName
                    'Version' = $App.DisplayVersion
                    'Publisher' = $App.Publisher
                    'InstallDate' = if ($App.InstallDate) {
                        try { [DateTime]::ParseExact($App.InstallDate, "yyyyMMdd", $null) }
                        catch { $App.InstallDate }
                    } else { $null }
                    'InstallLocation' = $App.InstallLocation
                    'UninstallString' = $App.UninstallString
                    'QuietUninstallString' = $App.QuietUninstallString
                    'EstimatedSize' = if ($App.EstimatedSize) { 
                        [math]::Round($App.EstimatedSize / 1024, 2) 
                    } else { $null }
                    'Architecture' = if ($Key -match "WOW6432Node") { "x86" } else { "x64" }
                    'Registry' = $App.PSPath -replace '.*::', ''
                    'ProductCode' = $App.PSChildName
                    'ModifyPath' = $App.ModifyPath
                    'HelpLink' = $App.HelpLink
                    'URLInfoAbout' = $App.URLInfoAbout
                    'Contact' = $App.Contact
                    'Comments' = $App.Comments
                    'WindowsInstaller' = if ($App.WindowsInstaller -eq 1) { $true } else { $false }
                    'SystemComponent' = if ($App.SystemComponent -eq 1) { $true } else { $false }
                    'IsUpdate' = if ($App.ParentKeyName) { $true } else { $false }
                }
            }
        }
        catch {
            Write-Warning "Error accessing registry key $Key : $_"
        }
    }
    
    return $Applications | Sort-Object DisplayName
}


# Basic installed applications (equivalent to Control Panel view)
Get-InstalledApplications | Select-Object DisplayName, Version, Publisher, InstallDate | Format-Table -AutoSize

# All applications with detailed information
Get-InstalledApplications | Format-Table -AutoSize

# Export to CSV for analysis
Get-InstalledApplications | Export-Csv -Path "InstalledApplications_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" -NoTypeInformation

# Applications installed in last 30 days
Get-InstalledApplications | Where-Object {$_.InstallDate -gt (Get-Date).AddDays(-30)} | Sort-Object InstallDate -Descending

# Applications without uninstall strings (potentially problematic)
Get-InstalledApplications | Where-Object {-not $_.UninstallString}
