# PowerShell script to download, install, and configure Microsoft Sysinternals Suite
# Requires Administrator privileges for creating directories in C:\

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script requires Administrator privileges to create directories in C:\" -ForegroundColor Red
    Write-Host "Please run PowerShell as Administrator and try again." -ForegroundColor Yellow
    exit 1
}

# Define variables
$downloadUrl = "https://download.sysinternals.com/files/SysinternalsSuite.zip"
$downloadPath = "$env:TEMP\SysinternalsSuite.zip"
$destinationPath = "C:\sysinternals"

Write-Host "Starting Sysinternals Suite installation..." -ForegroundColor Green

# Step 1: Download the Sysinternals Suite
Write-Host "Step 1: Downloading Sysinternals Suite from Microsoft..." -ForegroundColor Yellow
try {
    # Use Invoke-WebRequest to download the file
    Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadPath -UseBasicParsing
    Write-Host "Download completed successfully." -ForegroundColor Green
} catch {
    Write-Host "Error downloading Sysinternals Suite: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Verify download
if (-not (Test-Path $downloadPath)) {
    Write-Host "Download failed - file not found at $downloadPath" -ForegroundColor Red
    exit 1
}

Write-Host "Downloaded file size: $([math]::Round((Get-Item $downloadPath).Length / 1MB, 2)) MB" -ForegroundColor Cyan

# Step 2: Create destination directory and extract
Write-Host "Step 2: Creating destination directory and extracting files..." -ForegroundColor Yellow
try {
    # Create destination directory if it doesn't exist
    if (-not (Test-Path $destinationPath)) {
        New-Item -ItemType Directory -Path $destinationPath -Force | Out-Null
        Write-Host "Created directory: $destinationPath" -ForegroundColor Green
    } else {
        Write-Host "Directory already exists: $destinationPath" -ForegroundColor Cyan
    }

    # Extract the ZIP file
    Expand-Archive -Path $downloadPath -DestinationPath $destinationPath -Force
    Write-Host "Extraction completed successfully." -ForegroundColor Green
    
    # Count extracted files
    $fileCount = (Get-ChildItem $destinationPath -File).Count
    Write-Host "Extracted $fileCount files to $destinationPath" -ForegroundColor Cyan
    
} catch {
    Write-Host "Error extracting files: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Step 3: Set registry key to accept EULA
Write-Host "Step 3: Setting registry key to accept Sysinternals EULA..." -ForegroundColor Yellow
try {
    # Create the registry path if it doesn't exist
    $regPath = "HKCU:\Software\Sysinternals"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
        Write-Host "Created registry path: $regPath" -ForegroundColor Green
    }

    # Set the EulaAccepted value
    Set-ItemProperty -Path $regPath -Name "EulaAccepted" -Value 1 -Type DWord
    Write-Host "EULA accepted for current user." -ForegroundColor Green
    
    # Verify the registry setting
    $eulaValue = Get-ItemProperty -Path $regPath -Name "EulaAccepted" -ErrorAction SilentlyContinue
    if ($eulaValue.EulaAccepted -eq 1) {
        Write-Host "Registry setting verified: EulaAccepted = 1" -ForegroundColor Green
    } else {
        Write-Host "Warning: Could not verify registry setting" -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "Error setting registry key: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Clean up downloaded file
Write-Host "Cleaning up temporary files..." -ForegroundColor Yellow
try {
    Remove-Item $downloadPath -Force
    Write-Host "Temporary download file removed." -ForegroundColor Green
} catch {
    Write-Host "Warning: Could not remove temporary file: $downloadPath" -ForegroundColor Yellow
}

# Optional: Add to PATH environment variable
Write-Host ""
Write-Host "Installation completed successfully!" -ForegroundColor Green
Write-Host "Sysinternals tools are installed in: $destinationPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "Optional: To add Sysinternals to your PATH environment variable, run:" -ForegroundColor Yellow
Write-Host "  [Environment]::SetEnvironmentVariable('PATH', `$env:PATH + ';C:\sysinternals', 'User')" -ForegroundColor White
Write-Host ""
Write-Host "You can now run Sysinternals tools without EULA prompts." -ForegroundColor Green

# Display some example tools
Write-Host ""
Write-Host "Popular Sysinternals tools now available:" -ForegroundColor Cyan
$commonTools = @("Process Explorer (procexp.exe)", "Process Monitor (procmon.exe)", "Autoruns (autoruns.exe)", "PsExec (psexec.exe)", "TCPView (tcpview.exe)")
foreach ($tool in $commonTools) {
    Write-Host "  • $tool" -ForegroundColor White
}
