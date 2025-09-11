Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, 
    HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | 
    Where-Object {$_.DisplayName} | 
    Select-Object DisplayName, DisplayVersion, Publisher, `
    @{Name="Size(MB)";Expression={[math]::Round($_.EstimatedSize/1024,2)}} | 
    Sort-Object DisplayName
