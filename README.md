# BloodHoundOperator

PowerShell client for [BloodHound Community Edition](https://github.com/SpecterOps/BloodHound) and [BloodHound Enterprise](https://specterops.io/bloodhound-overview/)

Learn more:
- Release blog post: [BloodHound Operator — Dog Whispering Reloaded](https://specterops.io/blog/2024/08/06/bloodhound-operator-dog-whispering-reloaded/)
- Presentation at PowerShell Conference Europe: [The Dog Ate My Homework - A new chapter in my BloodHound adventures with PowerShell](https://www.youtube.com/watch?v=K-zNjWvFIPQ)


# Getting Started

## Authenticate
Create an API token ID/Key pair from the BloodHound browser UI - in [Working with the BloodHound API](https://support.bloodhoundenterprise.io/hc/en-us/articles/11311053342619-Working-with-the-BloodHound-API) follow either section:

- Create a non-personal API key/ID pair
- Create a personal API Key/ID pair

Copy the generated TokenID to your clipbard, then load to variable
```PowerShell
# Get id from clipboard
$BHTokenID = Get-Clipboard
```

Copy the generated TokenKey to your clipbard, then load to variable as SecureString
```PowerShell
# Get key from Clipboard
$BHTokenKey = Get-Clipboard | Convertto-SecureString -AsPlainText -Force
```

Create BHSession (BHCE)
```PowerShell
# Create Session - BHCE, defaults to 127.0.0.1
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

## Running Cmdlets
List BloodHoundOperator Cmdlets
```PowerShell
# Cmdlet Cheat
BHHelp
# Online
BHHelp -Online
```

Check current user (Whoami)
```PowerShell
# Whoami
BHRole -Whoami
BHOperator -Whoami
```

Run Cypher query
```PowerShell
# List Kerberoastable users
BHCypher -Query 'MATCH (n:User) WHERE n.hasspn=true RETURN n'
```