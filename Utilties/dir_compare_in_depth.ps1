# Directory Comparison Script
# Compares two directories and provides detailed analysis

# Define directories - Update these with your primary and secondary directory.
$Dir1 = "C:\Data1"
$Dir2 = "D:\Data2"

Write-Host "=== Directory Comparison Analysis ===" -ForegroundColor Green
Write-Host "Dir1: $Dir1" -ForegroundColor Yellow
Write-Host "Dir2: $Dir2" -ForegroundColor Yellow
Write-Host ""

# Check if directories exist
if (!(Test-Path $Dir1)) {
    Write-Error "Directory 1 does not exist: $Dir1"
    exit 1
}
if (!(Test-Path $Dir2)) {
    Write-Error "Directory 2 does not exist: $Dir2"
    exit 1
}

# Function to get directory statistics
function Get-DirectoryStats {
    param($Path)
    
    $files = Get-ChildItem -Path $Path -Recurse -File
    $totalSize = ($files | Measure-Object -Property Length -Sum).Sum
    $totalSizeMB = [Math]::Round($totalSize / 1MB, 2)
    
    return @{
        FileCount = $files.Count
        TotalSizeMB = $totalSizeMB
        Files = $files
    }
}

# Function to get file info with hash
function Get-FileInfoWithHash {
    param($Files, $BasePath)
    
    $fileInfo = @{}
    $counter = 0
    
    foreach ($file in $Files) {
        $counter++
        $relativePath = $file.FullName.Replace($BasePath + "\", "")
        Write-Progress -Activity "Calculating hashes" -Status "Processing $relativePath" -PercentComplete (($counter / $Files.Count) * 100)
        
        $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256
        $fileInfo[$relativePath] = @{
            FullPath = $file.FullName
            Hash = $hash.Hash
            Size = $file.Length
            LastWriteTime = $file.LastWriteTime
        }
    }
    Write-Progress -Activity "Calculating hashes" -Completed
    return $fileInfo
}

Write-Host "1. Getting directory statistics..." -ForegroundColor Cyan

# Get directory statistics
$dir1Stats = Get-DirectoryStats -Path $Dir1
$dir2Stats = Get-DirectoryStats -Path $Dir2

Write-Host ""
Write-Host "=== DIRECTORY STATISTICS ===" -ForegroundColor Green
Write-Host "Dir1 ($Dir1):" -ForegroundColor Yellow
Write-Host "  Files: $($dir1Stats.FileCount)"
Write-Host "  Total Size: $($dir1Stats.TotalSizeMB) MB"
Write-Host ""
Write-Host "Dir2 ($Dir2):" -ForegroundColor Yellow
Write-Host "  Files: $($dir2Stats.FileCount)"
Write-Host "  Total Size: $($dir2Stats.TotalSizeMB) MB"
Write-Host ""

Write-Host "2. Calculating file hashes for Dir1..." -ForegroundColor Cyan
$dir1FileInfo = Get-FileInfoWithHash -Files $dir1Stats.Files -BasePath $Dir1

Write-Host "3. Calculating file hashes for Dir2..." -ForegroundColor Cyan
$dir2FileInfo = Get-FileInfoWithHash -Files $dir2Stats.Files -BasePath $Dir2

# Find files in Dir1 but not in Dir2
$filesOnlyInDir1 = @()
foreach ($file in $dir1FileInfo.Keys) {
    if (!$dir2FileInfo.ContainsKey($file)) {
        $filesOnlyInDir1 += $file
    }
}

# Find files in Dir2 but not in Dir1
$filesOnlyInDir2 = @()
foreach ($file in $dir2FileInfo.Keys) {
    if (!$dir1FileInfo.ContainsKey($file)) {
        $filesOnlyInDir2 += $file
    }
}

# Find files with different hashes
$filesWithDifferentHashes = @()
foreach ($file in $dir1FileInfo.Keys) {
    if ($dir2FileInfo.ContainsKey($file)) {
        if ($dir1FileInfo[$file].Hash -ne $dir2FileInfo[$file].Hash) {
            $filesWithDifferentHashes += @{
                FileName = $file
                Dir1Hash = $dir1FileInfo[$file].Hash
                Dir2Hash = $dir2FileInfo[$file].Hash
                Dir1Size = $dir1FileInfo[$file].Size
                Dir2Size = $dir2FileInfo[$file].Size
                Dir1Modified = $dir1FileInfo[$file].LastWriteTime
                Dir2Modified = $dir2FileInfo[$file].LastWriteTime
            }
        }
    }
}

# Display results
Write-Host ""
Write-Host "=== FILES ONLY IN DIR1 (NOT IN DIR2) ===" -ForegroundColor Green
if ($filesOnlyInDir1.Count -eq 0) {
    Write-Host "No files found only in Dir1" -ForegroundColor Gray
} else {
    Write-Host "Count: $($filesOnlyInDir1.Count)" -ForegroundColor Yellow
    $filesOnlyInDir1 | Sort-Object | ForEach-Object { Write-Host "  $_" }
}

Write-Host ""
Write-Host "=== FILES ONLY IN DIR2 (NOT IN DIR1) ===" -ForegroundColor Green
if ($filesOnlyInDir2.Count -eq 0) {
    Write-Host "No files found only in Dir2" -ForegroundColor Gray
} else {
    Write-Host "Count: $($filesOnlyInDir2.Count)" -ForegroundColor Yellow
    $filesOnlyInDir2 | Sort-Object | ForEach-Object { Write-Host "  $_" }
}

Write-Host ""
Write-Host "=== FILES WITH DIFFERENT CONTENT (DIFFERENT SHA HASHES) ===" -ForegroundColor Green
if ($filesWithDifferentHashes.Count -eq 0) {
    Write-Host "No files with different content found" -ForegroundColor Gray
} else {
    Write-Host "Count: $($filesWithDifferentHashes.Count)" -ForegroundColor Yellow
    foreach ($file in $filesWithDifferentHashes) {
        Write-Host ""
        Write-Host "File: $($file.FileName)" -ForegroundColor White
        Write-Host "  Dir1 Hash: $($file.Dir1Hash)" -ForegroundColor Red
        Write-Host "  Dir2 Hash: $($file.Dir2Hash)" -ForegroundColor Red
        Write-Host "  Dir1 Size: $($file.Dir1Size) bytes, Modified: $($file.Dir1Modified)"
        Write-Host "  Dir2 Size: $($file.Dir2Size) bytes, Modified: $($file.Dir2Modified)"
    }
}

# Summary
Write-Host ""
Write-Host "=== SUMMARY ===" -ForegroundColor Green
Write-Host "Files only in Dir1: $($filesOnlyInDir1.Count)"
Write-Host "Files only in Dir2: $($filesOnlyInDir2.Count)"
Write-Host "Files with different content: $($filesWithDifferentHashes.Count)"
$commonFiles = 0
foreach ($file in $dir1FileInfo.Keys) {
    if ($dir2FileInfo.ContainsKey($file) -and $dir1FileInfo[$file].Hash -eq $dir2FileInfo[$file].Hash) {
        $commonFiles++
    }
}
Write-Host "Identical files in both directories: $commonFiles"

Write-Host ""
Write-Host "Analysis complete!" -ForegroundColor Green
