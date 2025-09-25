# PowerShell script to find all .docx files in "drive-letter:\path" and subdirectories
# that were created or modified in August 2025 

# Define the search path and date range = MODIFY AS NEEDED for your work effort.
$SearchPath = "drive-letter:\path"
$StartDate = Get-Date "2025-08-01"
$EndDate = Get-Date "2025-08-31 23:59:59"

# Check if the search path exists
if (-not (Test-Path $SearchPath)) {
    Write-Error "Path '$SearchPath' does not exist or is not accessible."
    exit 1
}

Write-Host "Searching for .docx files in '$SearchPath' and subdirectories..." -ForegroundColor Green
Write-Host "Date range: August 1, 2025 to August 31, 2025" -ForegroundColor Green
Write-Host ""

try {
    # Get all .docx files recursively
    $DocxFiles = Get-ChildItem -Path $SearchPath -Filter "*.docx" -Recurse -File | Where-Object {
        # Filter by creation time OR last write time within August 2025
        ($_.CreationTime -ge $StartDate -and $_.CreationTime -le $EndDate) -or
        ($_.LastWriteTime -ge $StartDate -and $_.LastWriteTime -le $EndDate)
    }

    if ($DocxFiles.Count -eq 0) {
        Write-Host "No .docx files found that were created or modified in August 2025." -ForegroundColor Yellow
    } else {
        Write-Host "Found $($DocxFiles.Count) .docx file(s):" -ForegroundColor Green
        Write-Host ""
        
        # Display results in a formatted table
        $DocxFiles | Select-Object @{
            Name = "File Name"
            Expression = { $_.Name }
        }, @{
            Name = "Full Path"
            Expression = { $_.FullName }
        }, @{
            Name = "Size (KB)"
            Expression = { [math]::Round($_.Length / 1KB, 2) }
        }, @{
            Name = "Created"
            Expression = { $_.CreationTime.ToString("yyyy-MM-dd HH:mm:ss") }
        }, @{
            Name = "Modified"
            Expression = { $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss") }
        } | Format-Table -AutoSize

        # Optional: Export to CSV file
        $ExportPath = ".\docx_files_august_2025.csv"
        $DocxFiles | Select-Object Name, FullName, 
            @{Name="Size_KB"; Expression={[math]::Round($_.Length / 1KB, 2)}},
            @{Name="Created"; Expression={$_.CreationTime}},
            @{Name="Modified"; Expression={$_.LastWriteTime}} | 
            Export-Csv -Path $ExportPath -NoTypeInformation
        
        Write-Host ""
        Write-Host "Results also exported to: $ExportPath" -ForegroundColor Cyan
    }
} catch {
    Write-Error "An error occurred while searching: $($_.Exception.Message)"
    exit 1
}
