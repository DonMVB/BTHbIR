# CONFIGURATION
$resourceGroup = "YourResourceGroup"
$vmName = "YourVMName"
$storageAccountName = "YourStorageAccount"
$location = "eastus"  # Match VM region
$durationSeconds = 3600  # 1 hour
$loopCount = 3  # Number of captures (adjust as needed)

# LOGIN
Connect-AzAccount

# GET VM DETAILS
$vm = Get-AzVM -ResourceGroupName $resourceGroup -Name $vmName
$vmId = $vm.Id

# GET STORAGE ACCOUNT DETAILS
$storageAccount = Get-AzStorageAccount -ResourceGroupName $resourceGroup -Name $storageAccountName
$storageId = $storageAccount.Id
$storageKey = (Get-AzStorageAccountKey -ResourceGroupName $resourceGroup -Name $storageAccountName)[0].Value
$storageContext = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $storageKey

# LOOP FOR HOURLY CAPTURE
for ($i = 1; $i -le $loopCount; $i++) {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $captureName = "pcap-$vmName-$timestamp"

    Write-Host "Starting capture $captureName..."

    # CREATE PACKET CAPTURE
    New-AzNetworkWatcherPacketCapture `
        -NetworkWatcherName "NetworkWatcher_$location" `
        -ResourceGroupName $resourceGroup `
        -TargetVirtualMachineId $vmId `
        -Name $captureName `
        -StorageAccountId $storageId `
        -TimeLimitInSeconds $durationSeconds `
        -FilePath "captures/$captureName.pcap"

    # WAIT FOR CAPTURE TO COMPLETE
    Start-Sleep -Seconds $durationSeconds

    Write-Host "Capture $captureName completed.`n"
}
