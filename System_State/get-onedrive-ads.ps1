# Find the user's profile path
$userProfile = [Environment]::GetFolderPath("UserProfile")

# Determine if OneDrive is in use
$oneDrivePath = "$userProfile\OneDrive"
$basePath = if (Test-Path $oneDrivePath) { $oneDrivePath } else { $userProfile }

Write-Host "Searching $basePath"
# Search for files with ADS; extract MOTW URLs
Get-ChildItem -Path $basePath -Recurse -Force -ErrorAction SilentlyContinue |
    Where-Object { -not $_.PSIsContainer } |
    ForEach-Object {
        try {
            $streams = Get-Item -Path $_.FullName -Stream * -ErrorAction Stop
            $zoneStream = $streams | Where-Object { $_.Stream -eq "Zone.Identifier" }
            if ($zoneStream) {
                $streamContent = Get-Content -Path $_.FullName -Stream "Zone.Identifier" -ErrorAction Stop
                $urlLine = $streamContent | Where-Object { $_ -match '^(ReferrerUrl|HostUrl)=' }
                if ($urlLine) {
                    [PSCustomObject]@{
                        File = $_.FullName
                        Stream = "Zone.Identifier"
                        URL = ($urlLine -replace '^(ReferrerUrl|HostUrl)=', '')
                    }
                }
            }
        } catch {
            Write-Verbose "Error processing $($_.FullName): $_"
        }
    }
