# BloodHoundOperator - Getting Started

TokenID from clipbard to variable
```PowerShell
# Get id from clipboard
$BHTokenID = Get-Clipboard
```

TokenKey from Clipboard to variable as SecureString
```PowerShell
# Get key from Clipboard
$BHTokenKey = Get-Clipboard | Convertto-SecureString -AsPlainText -Force
```
Create BHSession (BHCE)
```PowerShell
# Create Session - BHCE
New-BHSession -TokenID $BHTokenID -Token $BHTokenKey
```
-or-

Create BHSession (BHE)
```PowerShell
# Create Session - BHE
New-BHSession -Server test.bloodhoundenterprise.io -TokenID $BHETokenID -Token $BHETokenKey
```

Check Session Object
```PowerShell
# Check Session
BHSession | ft
```

Check current user (Whoami)
```PowerShell
# Whoami
BHRole -Whoami
BHOperator -Whoami
```
List BloodHoundOperator Cmdlets
```PowerShell
# Cmdlet Cheat
BHHelp
# Online
BHHelp -Online
```