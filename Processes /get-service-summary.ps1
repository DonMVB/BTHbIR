Write-Host "Analyzing Services..." -ForegroundColor Yellow
$Results = @{
    "Services" = @()
}

try {
    $services = Get-WmiObject Win32_Service | Where-Object { 
        $_.StartMode -eq "Auto" -or $_.StartMode -eq "Automatic"
    } | Select-Object Name, DisplayName, PathName, StartMode, StartName, State, ServiceType
    
    foreach ($service in $services) {        
        $Results.Services += @{
            Name = $service.Name
            DisplayName = $service.DisplayName
            PathName = $service.PathName
            StartMode = $service.StartMode
            StartName = $service.StartName
            State = $service.State
            ServiceType = $service.ServiceType
        }
    }
}
catch {
    Write-Warning "Error collecting services: $($_.Exception.Message)"
}

# Print out the results
Write-Host "`nSERVICES ANALYSIS RESULTS" -ForegroundColor Green
Write-Host "=========================" -ForegroundColor Green
Write-Host "Total Services Found: $($Results.Services.Count)" -ForegroundColor Cyan

if ($Results.Services.Count -gt 0) {
    foreach ($service in $Results.Services) {
        Write-Host "`n--- Service Details ---" -ForegroundColor Yellow
        Write-Host "Name: $($service.Name)" -ForegroundColor White
        Write-Host "Display Name: $($service.DisplayName)" -ForegroundColor White
        Write-Host "Path: $($service.PathName)" -ForegroundColor White
        Write-Host "Start Mode: $($service.StartMode)" -ForegroundColor White
        Write-Host "Start Name: $($service.StartName)" -ForegroundColor White
        Write-Host "State: $($service.State)" -ForegroundColor White
        Write-Host "Service Type: $($service.ServiceType)" -ForegroundColor White
        Write-Host $("-" * 40) -ForegroundColor DarkGray
    }
    
    # Alternative: Print as a formatted table (more compact)
    Write-Host "`nSUMMARY TABLE:" -ForegroundColor Green
    # Convert hashtables to objects that Format-Table can handle
    $Results.Services | ForEach-Object { 
        New-Object PSObject -Property $_ 
    } | Format-Table -Property Name, DisplayName, StartMode, State, StartName -Wrap  # 
    
    # Alternative: Export to CSV for external analysis
    # $Results.Services | Export-Csv -Path "Services_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" -NoTypeInformation
    # Write-Host "Results also exported to CSV file" -ForegroundColor Cyan
}
else {
    Write-Host "No automatic startup services found." -ForegroundColor Red
}
