# ***************************************************************************
# *  Script      : compare_asep_json_V_01.ps1
# *  Version     : V_01
# *  Last Update : 2026-08-03 16:59 EST
# *  Purpose     : Semantically compares two asep_analyzer JSON output files
# *                (a before and an after run) and reports per-category:
# *                  [NEW]     entries in AFTER not in BEFORE  (synthetic hits)
# *                  [REMOVED] entries in BEFORE not in AFTER
# *                  [CHANGED] entries present in both with differing values
# *                Identical entries are counted but not printed (keep it fast).
# *
# *  Typical use:
# *    1. Run asep_analyzer -> BEFORE.json
# *    2. Run synthetic test suite to enable all artifacts
# *    3. Run asep_analyzer -> AFTER.json
# *    4. .\compare_asep_json_V_01.ps1 -Before BEFORE.json -After AFTER.json
# *
# *  Command-line options:
# *     -Before  <path>   Path to the first (before) JSON file.
# *                       If omitted, the script finds the two most recent
# *                       ASEP_L*.json files in the current folder and uses
# *                       the older one as Before.
# *     -After   <path>   Path to the second (after) JSON file.
# *                       If omitted, uses the newer auto-discovered file.
# *     -Category <name>  Limit output to one named category (partial match).
# *     -NewOnly          Show only NEW entries (suppresses REMOVED/CHANGED).
# *     -ExportCsv <path> Write all differences to a CSV file.
# ***************************************************************************

[CmdletBinding()]
param(
    [string]$Before,
    [string]$After,
    [string]$Category,
    [switch]$NewOnly,
    [string]$ExportCsv
)

# ---------------------------------------------------------------------------
# IDENTITY KEYS
#   Defines which properties uniquely identify a row within each category.
#   The comparison joins on these; everything else is a "value" to diff.
#   Must match the exact PSCustomObject property names used in 2.09+.
# ---------------------------------------------------------------------------
$IdentityKeys = @{
    RunKeys             = @("Name","Path")
    Services            = @("Name")
    ScheduledTasks      = @("TaskName","TaskPath")
    StartupFolders      = @("Name","Scope")
    Winlogon            = @("Name","Path")
    AppInit             = @("Name","Path")
    WMISubscriptions    = @("FilterName","ConsumerName","State")
    ShellExtensions     = @("Hive","Class","HandlerType","HandlerName")
    BrowserHelperObjects= @("CLSID")
    LSA                 = @("Name")
    ActiveSetup         = @("ComponentID")
    ImageFileExecution  = @("Executable")
    PowerShellProfiles  = @("ProfilePath")
    Drivers             = @("Name")
    NetworkProviders    = @("Name")
    WinsockProviders    = @("Catalog","Entry")
    COM                 = @("CLSID","Hive","ServerType")
    BootExecute         = @("Name")
    KnownDLLs           = @("Name")
    SessionManager      = @("Item","Name")
    ModernApps          = @("Package","TaskKey")
}

# ---------------------------------------------------------------------------
# AUTO-DISCOVER JSON FILES
# ---------------------------------------------------------------------------
function Find-AsepJsonFiles {
    param([string]$SearchDir)
    $files = Get-ChildItem -LiteralPath $SearchDir -Filter "ASEP_L*.json" -File |
             Sort-Object LastWriteTime -Descending |
             Select-Object -First 2
    if ($files.Count -lt 2) {
        Write-Error "Need at least 2 ASEP_L*.json files in '$SearchDir'. Found $($files.Count)."
        return $null
    }
    # Newer = After, Older = Before
    return @{ Before = $files[1]; After = $files[0] }
}

# ---------------------------------------------------------------------------
# BUILD IDENTITY KEY STRING from a row object
# ---------------------------------------------------------------------------
function Get-RowKey {
    param($Row, [string[]]$Keys)
    $parts = foreach ($k in $Keys) {
        $v = $Row.$k
        if ($null -eq $v) { "(null)" } else { [string]$v }
    }
    return $parts -join " | "
}

# ---------------------------------------------------------------------------
# SUMMARISE ROW for display (most informative non-key properties)
# ---------------------------------------------------------------------------
function Get-RowSummary {
    param($Row, [string[]]$SkipKeys)
    $allProps = $Row.PSObject.Properties |
        Where-Object { $_.Name -ne "Category" -and $_.Name -notin $SkipKeys }
    $parts = foreach ($p in $allProps | Select-Object -First 5) {
        $val = [string]$p.Value
        if ($val.Length -gt 60) { $val = $val.Substring(0,57) + "..." }
        if ($val) { "$($p.Name)=$val" }
    }
    return $parts -join "  "
}

# ---------------------------------------------------------------------------
# FIND CHANGED PROPERTIES between two matching rows
# ---------------------------------------------------------------------------
function Get-ChangedProps {
    param($RowA, $RowB)
    $changes = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $RowA.PSObject.Properties) {
        $vA = [string]$p.Value
        $vB = [string]($RowB.($p.Name))
        if ($vA -ne $vB) {
            $changes.Add("$($p.Name): '$vA' -> '$vB'")
        }
    }
    return $changes
}

# ---------------------------------------------------------------------------
# RESOLVE INPUT FILES
# ---------------------------------------------------------------------------
if ($Before -and $After) {
    if (-not (Test-Path -LiteralPath $Before)) { Write-Error "Before file not found: $Before"; return }
    if (-not (Test-Path -LiteralPath $After))  { Write-Error "After file not found: $After";  return }
    $beforeItem = Get-Item -LiteralPath $Before
    $afterItem  = Get-Item -LiteralPath $After
} else {
    $found = Find-AsepJsonFiles -SearchDir (Get-Location).Path
    if (-not $found) { return }
    $beforeItem = $found.Before
    $afterItem  = $found.After
    Write-Host "  Auto-discovered files:" -ForegroundColor DarkGray
    Write-Host ("    BEFORE: {0}" -f $beforeItem.Name) -ForegroundColor DarkGray
    Write-Host ("    AFTER : {0}" -f $afterItem.Name)  -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# LOAD JSON
# ---------------------------------------------------------------------------
try {
    $beforeData = Get-Content -LiteralPath $beforeItem.FullName -Raw | ConvertFrom-Json
    $afterData  = Get-Content -LiteralPath $afterItem.FullName  -Raw | ConvertFrom-Json
} catch {
    Write-Error "Failed to parse JSON: $($_.Exception.Message)"; return
}

# ---------------------------------------------------------------------------
# COUNT TOTAL ENTRIES IN EACH FILE
# ---------------------------------------------------------------------------
function Count-Entries { param($Data)
    $n = 0
    foreach ($key in $Data.PSObject.Properties.Name) {
        $val = $Data.$key
        if ($val -is [System.Object[]]) { $n += $val.Count }
    }
    return $n
}
$totalBefore = Count-Entries $beforeData
$totalAfter  = Count-Entries $afterData

# ---------------------------------------------------------------------------
# HEADER
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host ("  {0}" -f ("=" * 70)) -ForegroundColor Cyan
Write-Host "    ASEP Analyzer  -  Before / After Comparison"              -ForegroundColor Cyan
Write-Host ("  {0}" -f ("=" * 70)) -ForegroundColor Cyan
Write-Host ("    BEFORE : {0,-40} {1,6} entries" -f $beforeItem.Name, $totalBefore)
Write-Host ("    AFTER  : {0,-40} {1,6} entries" -f $afterItem.Name,  $totalAfter)
if ($totalAfter -gt $totalBefore) {
    Write-Host ("    DELTA  : +{0} entries" -f ($totalAfter - $totalBefore)) -ForegroundColor Green
} elseif ($totalAfter -lt $totalBefore) {
    Write-Host ("    DELTA  : {0} entries" -f ($totalAfter - $totalBefore)) -ForegroundColor Yellow
} else {
    Write-Host "    DELTA  : 0 entries (same total)" -ForegroundColor DarkGray
}
Write-Host ("  {0}" -f ("=" * 70)) -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------------------
# COMPARE CATEGORY BY CATEGORY
# ---------------------------------------------------------------------------
$allKeys = [System.Collections.Generic.SortedSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
$beforeData.PSObject.Properties.Name | ForEach-Object { $null = $allKeys.Add($_) }
$afterData.PSObject.Properties.Name  | ForEach-Object { $null = $allKeys.Add($_) }

$exportRows = [System.Collections.Generic.List[PSCustomObject]]::new()

$summaryRows = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($cat in $allKeys) {
    # Apply -Category filter if specified
    if ($Category -and $cat -notlike "*$Category*") { continue }

    # Skip non-array keys (e.g. SystemInfo, NotImplemented)
    $bArr = @($beforeData.$cat | Where-Object { $_ -is [PSCustomObject] })
    $aArr = @($afterData.$cat  | Where-Object { $_ -is [PSCustomObject] })

    # Skip categories with no data in either file
    if ($bArr.Count -eq 0 -and $aArr.Count -eq 0) { continue }

    # Get identity keys for this category; fall back to all string properties
    $idKeys = $IdentityKeys[$cat]
    if (-not $idKeys) {
        # Generic fallback: use the first 2 non-Category properties as identity
        $sample = if ($aArr.Count -gt 0) { $aArr[0] } else { $bArr[0] }
        $idKeys = @($sample.PSObject.Properties.Name |
                    Where-Object { $_ -ne "Category" } |
                    Select-Object -First 2)
    }

    # Index rows by identity key
    $bIndex = @{}
    foreach ($row in $bArr) { $k = Get-RowKey $row $idKeys; $bIndex[$k] = $row }
    $aIndex = @{}
    foreach ($row in $aArr) { $k = Get-RowKey $row $idKeys; $aIndex[$k] = $row }

    $catNew = 0; $catRemoved = 0; $catChanged = 0; $catSame = 0
    $catLines = [System.Collections.Generic.List[string]]::new()

    # NEW entries (in AFTER, not in BEFORE)
    foreach ($k in ($aIndex.Keys | Sort-Object)) {
        if (-not $bIndex.ContainsKey($k)) {
            $catNew++
            $summary = Get-RowSummary -Row $aIndex[$k] -SkipKeys $idKeys
            $catLines.Add(("    [NEW]     {0}  |  {1}" -f $k, $summary))
            $exportRows.Add([PSCustomObject]@{ File="AFTER"; Change="NEW"; Category=$cat; Key=$k; Detail=$summary })
        }
    }

    # REMOVED entries (in BEFORE, not in AFTER)
    if (-not $NewOnly) {
        foreach ($k in ($bIndex.Keys | Sort-Object)) {
            if (-not $aIndex.ContainsKey($k)) {
                $catRemoved++
                $summary = Get-RowSummary -Row $bIndex[$k] -SkipKeys $idKeys
                $catLines.Add(("    [REMOVED] {0}  |  {1}" -f $k, $summary))
                $exportRows.Add([PSCustomObject]@{ File="BEFORE"; Change="REMOVED"; Category=$cat; Key=$k; Detail=$summary })
            }
        }

        # CHANGED entries (key present in both, but values differ)
        foreach ($k in ($bIndex.Keys | Sort-Object)) {
            if ($aIndex.ContainsKey($k)) {
                $diffs = Get-ChangedProps -RowA $bIndex[$k] -RowB $aIndex[$k]
                if ($diffs.Count -gt 0) {
                    $catChanged++
                    $catLines.Add(("    [CHANGED] {0}" -f $k))
                    foreach ($d in $diffs) { $catLines.Add(("              {0}" -f $d)) }
                    $exportRows.Add([PSCustomObject]@{ File="BOTH"; Change="CHANGED"; Category=$cat; Key=$k; Detail=($diffs -join " ; ") })
                } else {
                    $catSame++
                }
            }
        }
    } else {
        # NewOnly mode: still count same/removed for summary
        foreach ($k in $bIndex.Keys) {
            if ($aIndex.ContainsKey($k)) { $catSame++ } else { $catRemoved++ }
        }
    }

    # Print category block only if there are differences (or -Category was specified)
    $hasDiffs = ($catNew + $catRemoved + $catChanged) -gt 0
    if ($hasDiffs -or $Category) {
        $headerColor = if ($catNew -gt 0)     { "Green"  } `
                  elseif ($catRemoved -gt 0)  { "Red"    } `
                  elseif ($catChanged -gt 0)  { "Yellow" } `
                  else                        { "DarkGray" }
        Write-Host ("  ---- {0}  ({1} new  {2} removed  {3} changed  {4} identical)" -f `
            $cat, $catNew, $catRemoved, $catChanged, $catSame) -ForegroundColor $headerColor

        foreach ($line in $catLines) {
            $lineColor = if ($line -like "*[NEW]*")     { "Green"  } `
                    elseif ($line -like "*[REMOVED]*")  { "Red"    } `
                    elseif ($line -like "*[CHANGED]*")  { "Yellow" } `
                    else                                { "DarkGray" }
            Write-Host $line -ForegroundColor $lineColor
        }
        Write-Host ""
    }

    $summaryRows.Add([PSCustomObject]@{
        Category = $cat
        Before   = $bArr.Count
        After    = $aArr.Count
        New      = $catNew
        Removed  = $catRemoved
        Changed  = $catChanged
        Identical= $catSame
    })
}

# ---------------------------------------------------------------------------
# SUMMARY TABLE
# ---------------------------------------------------------------------------
$totalNew     = ($summaryRows | Measure-Object -Property New     -Sum).Sum
$totalRemoved = ($summaryRows | Measure-Object -Property Removed -Sum).Sum
$totalChanged = ($summaryRows | Measure-Object -Property Changed -Sum).Sum

Write-Host ("  {0}" -f ("=" * 70)) -ForegroundColor Cyan
Write-Host "    SUMMARY BY CATEGORY" -ForegroundColor Cyan
Write-Host ("  {0}" -f ("=" * 70)) -ForegroundColor Cyan
Write-Host ("    {0,-26} {1,7} {2,7} {3,5} {4,8} {5,8}" -f `
    "Category", "Before", "After", "New", "Removed", "Changed") -ForegroundColor Cyan
Write-Host ("    {0}" -f ("-" * 65)) -ForegroundColor DarkGray

foreach ($r in $summaryRows | Sort-Object { -($_.New + $_.Removed + $_.Changed) }) {
    $rowColor = if ($r.New -gt 0 -or $r.Removed -gt 0 -or $r.Changed -gt 0) { "White" } else { "DarkGray" }
    Write-Host ("    {0,-26} {1,7} {2,7} {3,5} {4,8} {5,8}" -f `
        $r.Category, $r.Before, $r.After, $r.New, $r.Removed, $r.Changed) -ForegroundColor $rowColor
}

Write-Host ("    {0}" -f ("-" * 65)) -ForegroundColor DarkGray
Write-Host ("    {0,-26} {1,7} {2,7} {3,5} {4,8} {5,8}" -f `
    "TOTAL", $totalBefore, $totalAfter, $totalNew, $totalRemoved, $totalChanged) -ForegroundColor Cyan
Write-Host ""

# Coverage check: are the expected synthetic artifacts present as NEW?
$expectedCategories = @("RunKeys","Services","ScheduledTasks","StartupFolders",
    "WMISubscriptions","BrowserHelperObjects","ShellExtensions","ActiveSetup",
    "ImageFileExecution","PowerShellProfiles","COM","SessionManager","ModernApps")
$seededCats  = $summaryRows | Where-Object { $_.New -gt 0 } | Select-Object -ExpandProperty Category
$missedCats  = $expectedCategories | Where-Object { $_ -notin $seededCats }
if ($missedCats) {
    Write-Host "  !! Seeder categories with no NEW entries detected:" -ForegroundColor Yellow
    $missedCats | ForEach-Object { Write-Host "       $_" -ForegroundColor Yellow }
    Write-Host ""
}

# ---------------------------------------------------------------------------
# OPTIONAL CSV EXPORT
# ---------------------------------------------------------------------------
if ($ExportCsv) {
    try {
        $exportRows | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
        Write-Host ("  Differences exported to: {0}" -f $ExportCsv) -ForegroundColor DarkGray
        Write-Host ""
    } catch {
        Write-Warning "Could not write CSV: $($_.Exception.Message)"
    }
}
