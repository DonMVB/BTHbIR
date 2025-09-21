# Directory Comparison Script
# Compares two directories and provides detailed analysis

# Define directories - Update these with your primary and secondary directory.
$Dir1 = "C:\Data1"
$Dir2 = "D:\Data2"

# Define file extensions to exclude from SHA hash comparison
$excludedExtensions = @(".iso", ".tmp")

Write-Host "=== DIRECTORY COMPARISON ANALYSIS ===" -ForegroundColor Green
Write-Host "Primary Directory (Dir1): $Dir1" -ForegroundColor Yellow
Write-Host "Secondary Directory (Dir2): $Dir2" -ForegroundColor Yellow
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

# Function to get basic file info without hash
function Get-BasicFileInfo {
    param($Files, $BasePath)
    
    $fileInfo = @{}
    
    foreach ($file in $Files) {
        $relativePath = $file.FullName.Replace($BasePath + "\", "")
        $fileInfo[$relativePath] = @{
            FullPath = $file.FullName
            Size = $file.Length
            LastWriteTime = $file.LastWriteTime
            CreationTime = $file.CreationTime
            Extension = $file.Extension.ToLower()
        }
    }
    return $fileInfo
}

Write-Host "1. Analyzing directory contents..." -ForegroundColor Cyan

# Get directory statistics
$dir1Stats = Get-DirectoryStats -Path $Dir1
$dir2Stats = Get-DirectoryStats -Path $Dir2

Write-Host ""
Write-Host "=== DIRECTORY STATISTICS AND FILE COUNTS ===" -ForegroundColor Green
Write-Host "Primary Directory (Dir1): $Dir1" -ForegroundColor Yellow
Write-Host "  Files: $($dir1Stats.FileCount)"
Write-Host "  Total Size: $($dir1Stats.TotalSizeMB) MB"
Write-Host ""
Write-Host "Secondary Directory (Dir2): $Dir2" -ForegroundColor Yellow
Write-Host "  Files: $($dir2Stats.FileCount)"
Write-Host "  Total Size: $($dir2Stats.TotalSizeMB) MB"
Write-Host ""

Write-Host "2. Getting basic file information..." -ForegroundColor Cyan
$dir1FileInfo = Get-BasicFileInfo -Files $dir1Stats.Files -BasePath $Dir1
$dir2FileInfo = Get-BasicFileInfo -Files $dir2Stats.Files -BasePath $Dir2

# Find files in Dir1 but not in Dir2
$filesOnlyInDir1 = @()
foreach ($file in $dir1FileInfo.Keys) {
    if (!$dir2FileInfo.ContainsKey($file)) {
        $filesOnlyInDir1 += $dir1FileInfo[$file].FullPath
    }
}

# Find files in Dir2 but not in Dir1
$filesOnlyInDir2 = @()
foreach ($file in $dir2FileInfo.Keys) {
    if (!$dir1FileInfo.ContainsKey($file)) {
        $filesOnlyInDir2 += $dir2FileInfo[$file].FullPath
    }
}

# Display basic comparison results
Write-Host ""
Write-Host "=== FILES PRESENT IN PRIMARY DIRECTORY ONLY ===" -ForegroundColor Green
Write-Host "Primary Directory (Dir1): $Dir1" -ForegroundColor Yellow
if ($filesOnlyInDir1.Count -eq 0) {
    Write-Host "No files found only in Primary Directory" -ForegroundColor Gray
} else {
    Write-Host "Count: $($filesOnlyInDir1.Count)" -ForegroundColor White
    $filesOnlyInDir1 | Sort-Object | ForEach-Object { Write-Host "  $_" }
}

Write-Host ""
Write-Host "=== FILES PRESENT IN SECONDARY DIRECTORY ONLY ===" -ForegroundColor Green
Write-Host "Secondary Directory (Dir2): $Dir2" -ForegroundColor Yellow
if ($filesOnlyInDir2.Count -eq 0) {
    Write-Host "No files found only in Secondary Directory" -ForegroundColor Gray
} else {
    Write-Host "Count: $($filesOnlyInDir2.Count)" -ForegroundColor White
    $filesOnlyInDir2 | Sort-Object | ForEach-Object { Write-Host "  $_" }
}

Write-Host ""
Write-Host "=== DETAILED CONTENT COMPARISON BY FILE TYPE ===" -ForegroundColor Green
Write-Host "Starting detailed analysis of files present in both directories..." -ForegroundColor Cyan
Write-Host ""

# Separate files into excluded and hash-check categories
$excludedFiles = @()
$hashCheckFiles = @()

foreach ($file in $dir1FileInfo.Keys) {
    if ($dir2FileInfo.ContainsKey($file)) {
        $fileExtension = $dir1FileInfo[$file].Extension
        if ($excludedExtensions -contains $fileExtension) {
            $excludedFiles += @{
                RelativePath = $file
                Dir1Info = $dir1FileInfo[$file]
                Dir2Info = $dir2FileInfo[$file]
                Extension = $fileExtension
            }
        } else {
            $hashCheckFiles += @{
                RelativePath = $file
                Dir1Info = $dir1FileInfo[$file]
                Dir2Info = $dir2FileInfo[$file]
            }
        }
    }
}

# Function to get creation time difference analysis
function Get-CreationTimeDifference {
    param($Time1, $Time2)
    
    $timeDiff = $Time1 - $Time2
    $absDays = [Math]::Abs($timeDiff.Days)
    $absHours = [Math]::Abs($timeDiff.Hours)
    
    if ($Time1 -eq $Time2) {
        return "Same Create Date"
    } elseif ($Time1 -lt $Time2) {
        if ($absDays -eq 0 -and $absHours -eq 0) {
            return "Dir1 earlier than Dir2 (less than 1 hour)"
        } else {
            return "Dir1 earlier than Dir2 ($absDays days, $absHours hours)"
        }
    } else {
        if ($absDays -eq 0 -and $absHours -eq 0) {
            return "Dir2 earlier than Dir1 (less than 1 hour)"
        } else {
            return "Dir2 earlier than Dir1 ($absDays days, $absHours hours)"
        }
    }
}

# Display excluded files (by extension) comparison
Write-Host "=== LARGE/SPECIAL FILES COMPARISON (No Hash Check) ===" -ForegroundColor Green
Write-Host "File types excluded from hash comparison: $($excludedExtensions -join ', ')" -ForegroundColor Yellow
Write-Host ""

if ($excludedFiles.Count -eq 0) {
    Write-Host "No files with excluded extensions found in both directories" -ForegroundColor Gray
} else {
    Write-Host "Count: $($excludedFiles.Count)" -ForegroundColor White
    foreach ($file in $excludedFiles | Sort-Object RelativePath) {
        Write-Host ""
        Write-Host "File: $($file.RelativePath)" -ForegroundColor White
        Write-Host "  Dir1: $($file.Dir1Info.FullPath)"
        Write-Host "    Created: $($file.Dir1Info.CreationTime)"
        Write-Host "    Size: $($file.Dir1Info.Size) bytes"
        Write-Host "  Dir2: $($file.Dir2Info.FullPath)"
        Write-Host "    Created: $($file.Dir2Info.CreationTime)"
        Write-Host "    Size: $($file.Dir2Info.Size) bytes"
        
        # Creation time analysis
        $creationAnalysis = Get-CreationTimeDifference -Time1 $file.Dir1Info.CreationTime -Time2 $file.Dir2Info.CreationTime
        Write-Host "    CREATION TIME: $creationAnalysis" -ForegroundColor Cyan
        
        # Check if they're different
        if ($file.Dir1Info.Size -ne $file.Dir2Info.Size -or $file.Dir1Info.CreationTime -ne $file.Dir2Info.CreationTime) {
            Write-Host "    STATUS: DIFFERENT (Size or Creation Date)" -ForegroundColor Red
        } else {
            Write-Host "    STATUS: SAME (Size and Creation Date)" -ForegroundColor Green
        }
    }
}

# Now perform hash comparison on remaining files
Write-Host ""
Write-Host "=== HASH-BASED CONTENT COMPARISON ===" -ForegroundColor Green
Write-Host "Calculating SHA-256 hashes for detailed content comparison..." -ForegroundColor Cyan

$filesWithDifferentHashes = @()
$counter = 0

foreach ($fileObj in $hashCheckFiles) {
    $counter++
    $file = $fileObj.RelativePath
    Write-Progress -Activity "Comparing file content (SHA-256)" -Status "Processing $file" -PercentComplete (($counter / $hashCheckFiles.Count) * 100)
    
    $dir1Hash = Get-FileHash -Path $fileObj.Dir1Info.FullPath -Algorithm SHA256
    $dir2Hash = Get-FileHash -Path $fileObj.Dir2Info.FullPath -Algorithm SHA256
    
    if ($dir1Hash.Hash -ne $dir2Hash.Hash) {
        $creationAnalysis = Get-CreationTimeDifference -Time1 $fileObj.Dir1Info.CreationTime -Time2 $fileObj.Dir2Info.CreationTime
        
        $filesWithDifferentHashes += @{
            RelativePath = $file
            Dir1FullPath = $fileObj.Dir1Info.FullPath
            Dir2FullPath = $fileObj.Dir2Info.FullPath
            Dir1Hash = $dir1Hash.Hash
            Dir2Hash = $dir2Hash.Hash
            Dir1Size = $fileObj.Dir1Info.Size
            Dir2Size = $fileObj.Dir2Info.Size
            Dir1Modified = $fileObj.Dir1Info.LastWriteTime
            Dir2Modified = $fileObj.Dir2Info.LastWriteTime
            Dir1Created = $fileObj.Dir1Info.CreationTime
            Dir2Created = $fileObj.Dir2Info.CreationTime
            CreationAnalysis = $creationAnalysis
        }
    }
}
Write-Progress -Activity "Comparing file content (SHA-256)" -Completed

# Display hash comparison results
Write-Host ""
if ($filesWithDifferentHashes.Count -eq 0) {
    Write-Host "No files with different SHA-256 hashes found" -ForegroundColor Gray
} else {
    Write-Host "Count: $($filesWithDifferentHashes.Count)" -ForegroundColor White
    foreach ($file in $filesWithDifferentHashes | Sort-Object RelativePath) {
        Write-Host ""
        Write-Host "File: $($file.RelativePath)" -ForegroundColor White
        Write-Host "  Dir1: $($file.Dir1FullPath)"
        Write-Host "    Hash: $($file.Dir1Hash)" -ForegroundColor Red
        Write-Host "    Size: $($file.Dir1Size) bytes, Modified: $($file.Dir1Modified)"
        Write-Host "    Created: $($file.Dir1Created)"
        Write-Host "  Dir2: $($file.Dir2FullPath)"
        Write-Host "    Hash: $($file.Dir2Hash)" -ForegroundColor Red
        Write-Host "    Size: $($file.Dir2Size) bytes, Modified: $($file.Dir2Modified)"
        Write-Host "    Created: $($file.Dir2Created)"
        Write-Host "    CREATION TIME: $($file.CreationAnalysis)" -ForegroundColor Cyan
    }
}

# Add creation time analysis for ALL files in both directories (incident response timeline)
Write-Host ""
Write-Host "=== INCIDENT RESPONSE TIMELINE ANALYSIS ===" -ForegroundColor Green
Write-Host "Creation time comparison for all files present in both directories" -ForegroundColor Yellow
Write-Host ""

$allCommonFiles = @()
foreach ($file in $dir1FileInfo.Keys) {
    if ($dir2FileInfo.ContainsKey($file)) {
        $creationAnalysis = Get-CreationTimeDifference -Time1 $dir1FileInfo[$file].CreationTime -Time2 $dir2FileInfo[$file].CreationTime
        $allCommonFiles += @{
            RelativePath = $file
            Dir1FullPath = $dir1FileInfo[$file].FullPath
            Dir2FullPath = $dir2FileInfo[$file].FullPath
            Dir1Created = $dir1FileInfo[$file].CreationTime
            Dir2Created = $dir2FileInfo[$file].CreationTime
            CreationAnalysis = $creationAnalysis
        }
    }
}

if ($allCommonFiles.Count -eq 0) {
    Write-Host "No common files found for timeline analysis" -ForegroundColor Gray
} else {
    Write-Host "Total files analyzed: $($allCommonFiles.Count)" -ForegroundColor White
    Write-Host ""
    
    # Group files by creation analysis for summary
    $creationGroups = $allCommonFiles | Group-Object CreationAnalysis
    Write-Host "TIMELINE SUMMARY:" -ForegroundColor Cyan
    foreach ($group in $creationGroups | Sort-Object Name) {
        Write-Host "  $($group.Name): $($group.Count) files" -ForegroundColor White
    }
    
    Write-Host ""
    Write-Host "DETAILED TIMELINE ANALYSIS:" -ForegroundColor Cyan
    foreach ($file in $allCommonFiles | Sort-Object RelativePath) {
        Write-Host ""
        Write-Host "File: $($file.RelativePath)" -ForegroundColor White
        Write-Host "  Dir1: $($file.Dir1FullPath) (Created: $($file.Dir1Created))"
        Write-Host "  Dir2: $($file.Dir2FullPath) (Created: $($file.Dir2Created))"
        Write-Host "  TIMELINE: $($file.CreationAnalysis)" -ForegroundColor Cyan
    }
}

# Final Summary
Write-Host ""
Write-Host "=== FINAL ANALYSIS SUMMARY ===" -ForegroundColor Green
Write-Host "Primary Directory: $Dir1" -ForegroundColor Yellow
Write-Host "Secondary Directory: $Dir2" -ForegroundColor Yellow
Write-Host ""
Write-Host "Files only in Primary Directory: $($filesOnlyInDir1.Count)"
Write-Host "Files only in Secondary Directory: $($filesOnlyInDir2.Count)"
Write-Host "Large/Special files compared (by size/date): $($excludedFiles.Count)"
Write-Host "Files with different content (SHA-256): $($filesWithDifferentHashes.Count)"

# Count identical files
$identicalFiles = $hashCheckFiles.Count - $filesWithDifferentHashes.Count
Write-Host "Identical files (same SHA-256 hash): $identicalFiles"

Write-Host ""
Write-Host "Analysis complete!" -ForegroundColor Green
