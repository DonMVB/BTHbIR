# Get current date/time and calculate yesterday
$now = Get-Date
$yesterday = $now.AddDays(-1)

Write-Host "Analyzing files on C:\ modified since: $($yesterday.ToString('yyyy-MM-dd HH:mm:ss'))" 
Write-Host "Current time: $($now.ToString('yyyy-MM-dd HH:mm:ss'))" 

# Function to get ADS count for a file
function Get-AlternateDataStreamCount {
    param([string]$FilePath)
    
    try {
        # Use Get-Item with -Stream * to get all streams
        $streams = Get-Item -Path $FilePath -Stream * -ErrorAction SilentlyContinue
        if ($streams) {
            # Count streams (exclude the main :$DATA stream)
            $adsCount = ($streams | Where-Object { $_.Stream -ne ':$DATA' }).Count
            return $adsCount
        } else {
            return 0
        }
    } catch {
        return "Error"
    }
}

# Function to format file size in human readable format
function Format-FileSize {
    param([long]$Size)
    
    if ($Size -eq $null -or $Size -eq 0) { return "0 B" }   
    $units = @("B", "KB", "MB", "GB", "TB")
    $index = 0
    $sizeDouble = [double]$Size    
    while ($sizeDouble -ge 1024 -and $index -lt $units.Length - 1) {
        $sizeDouble /= 1024
        $index++
    }    
    return "{0:N2} {1}" -f $sizeDouble, $units[$index]
}

# Main analysis
try {
    $fileCount = 0
    
    Get-ChildItem -Path "C:\" -Recurse -File -ErrorAction SilentlyContinue | 
    Where-Object { $_.LastWriteTime -ge $yesterday } | 
    ForEach-Object {
        $fileCount++
        
        # Get ADS count
        $adsCount = Get-AlternateDataStreamCount -FilePath $_.FullName
        
        # Format file size
        $formattedSize = Format-FileSize -Size $_.Length
        
        # Create output object for better formatting
        $fileInfo = [PSCustomObject]@{
            'File Name' = $_.Name
            'Size (Bytes)' = $_.Length
            'Size (Formatted)' = $formattedSize
            'Full Path' = $_.FullName
            'Creation Time (UTC)' = $_.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
            'Last Access Time (UTC)' = $_.LastAccessTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
            'Last Write Time (UTC)' = $_.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
            'ADS Count' = $adsCount
        }
        
        # Display file information
        Write-Host ""
        Write-Host "File #$fileCount"
        Write-Host "Name: $($fileInfo.'File Name')" 
        Write-Host "Size: $($fileInfo.'Size (Formatted)') ($($fileInfo.'Size (Bytes)') bytes)" 
        Write-Host "Path: $($fileInfo.'Full Path')" 
        Write-Host "Created (UTC): $($fileInfo.'Creation Time (UTC)')" 
        Write-Host "Accessed (UTC): $($fileInfo.'Last Access Time (UTC)')"
        Write-Host "Modified (UTC): $($fileInfo.'Last Write Time (UTC)')"
        Write-Host "Alternate Data Streams: $($fileInfo.'ADS Count')" 
        
        # If ADS detected, show details
        if ($adsCount -gt 0 -and $adsCount -ne "Error") {
            Write-Host "ADS Details:" -ForegroundColor Yellow
            try {
                Get-Item -Path $_.FullName -Stream * -ErrorAction SilentlyContinue | 
                Where-Object { $_.Stream -ne ':$DATA' } | 
                ForEach-Object {
                    Write-Host "  Stream: $($_.Stream), Size: $(Format-FileSize -Size $_.Length)" 
                }
            } catch {
                Write-Host "  Could not retrieve ADS details" 
            }
        }
        
        Write-Host "-----"
    }
    
    Write-Host ""
    Write-Host "Analysis complete. Total files found: $fileCount" 
    
} catch {
    Write-Host "Error during analysis: $($_.Exception.Message)" 
}

# Optional: Export to CSV
$exportChoice = Read-Host "Would you like to export results to CSV? (y/n)"
if ($exportChoice -eq 'y' -or $exportChoice -eq 'Y') {
    $csvPath = "G:\file_analysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    
    try {
        Get-ChildItem -Path "G:\" -Recurse -File -ErrorAction SilentlyContinue | 
        Where-Object { $_.LastWriteTime -ge $yesterday } | 
        ForEach-Object {
            $adsCount = Get-AlternateDataStreamCount -FilePath $_.FullName
            
            [PSCustomObject]@{
                'FileName' = $_.Name
                'SizeBytes' = $_.Length
                'SizeFormatted' = Format-FileSize -Size $_.Length
                'FullPath' = $_.FullName
                'CreationTimeUTC' = $_.CreationTimeUtc
                'LastAccessTimeUTC' = $_.LastAccessTimeUtc
                'LastWriteTimeUTC' = $_.LastWriteTimeUtc
                'ADSCount' = $adsCount
                'Extension' = $_.Extension
                'Directory' = $_.DirectoryName
            }
        } | Export-Csv -Path $csvPath -NoTypeInformation
        
        Write-Host "Results exported to: $csvPath" 
    } catch {
        Write-Host "Error exporting CSV: $($_.Exception.Message)" 
    }
}
