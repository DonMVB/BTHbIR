# Import AD module if not already loaded
Import-Module ActiveDirectory

# Define the bitmask for TrustedForDelegation (Unconstrained Delegation)
$delegationFlag = 0x80000

# Search for user and computer accounts with the flag set
# Users Only: Get-ADUser -Filter 'TrustedForDelegation -eq $true' 
$accounts = Get-ADObject -Filter {
    (objectClass -eq "user" -or objectClass -eq "computer") -and
    (userAccountControl -band $delegationFlag)
} -Properties userAccountControl, Name, SamAccountName, objectClass

# Output results
$accounts | Select-Object Name, SamAccountName, objectClass, userAccountControl | Format-Table -AutoSize

