# Run as Administrator
# This code will enable maximum possible local audits in the windows event logs using auditpol and its subcategories
# also known as advanced auditing
# Turns all knobs to 11.
#
Write-Host "Enabling all audit subcategories for Success and Failure..." -ForegroundColor Cyan

# Get all subcategory names (first column only)
$auditSubcategories = auditpol /list /subcategory:* | ForEach-Object {
    if ($_ -match '^\s*(.+?)\s{2,}') { $matches[1].Trim() }
} | Where-Object { $_ -and $_ -ne "Subcategory Name" }

# Enable each subcategory
foreach ($sub in $auditSubcategories) {
    Write-Host "Setting: $sub"
    auditpol /set /subcategory:"$sub" /success:enable /failure:enable
}

Write-Host "`nAudit policy configuration complete." -ForegroundColor Green
auditpol /get /category:*
