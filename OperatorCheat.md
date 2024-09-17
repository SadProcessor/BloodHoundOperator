# BloodHoundOperator - CheatSheet
## Table Of Content
- [BHComposer](#bhcomposer)
    - [Get-BHComposer](#get-bhcomposer)
    - [Invoke-BHComposer](#invoke-bhcomposer)
    - [New-BHComposer](#new-bhcomposer)
    - [Get-BHComposerLog](#get-bhcomposerlog)
- [BHSession](#bhsession)
    - [Get-BHSession](#get-bhsession)
    - [New-BHSession](#new-bhsession)
    - [Remove-BHSession](#remove-bhsession)
    - [Select-BHSession](#select-bhsession)
    - [Set-BHSession](#set-bhsession)
    - [Invoke-BHSessionScript](#invoke-bhsessionscript)
- [BHAPI](#bhapi)
    - [Get-BHAPI](#get-bhapi)
    - [Invoke-BHAPI](#invoke-bhapi)
- [BHServer](#bhserver)
    - [Get-BHServerAuditLog](#get-bhserverauditlog)
    - [Get-BHServerConfig](#get-bhserverconfig)
    - [Set-BHServerConfig](#set-bhserverconfig)
    - [Get-BHServerFeature](#get-bhserverfeature)
    - [Set-BHServerFeature](#set-bhserverfeature)
    - [Get-BHServerSAMLEndpoint](#get-bhserversamlendpoint)
    - [Get-BHServerSAMLProvider](#get-bhserversamlprovider)
    - [New-BHServerSAMLProvider](#new-bhserversamlprovider)
    - [Remove-BHServerSAMLProvider](#remove-bhserversamlprovider)
    - [Get-BHServerVersion](#get-bhserverversion)
- [BHOperator](#bhoperator)
    - [Disable-BHOperator](#disable-bhoperator)
    - [Enable-BHOperator](#enable-bhoperator)
    - [Get-BHOperator](#get-bhoperator)
    - [New-BHOperator](#new-bhoperator)
    - [Remove-BHOperator](#remove-bhoperator)
    - [Set-BHOperator](#set-bhoperator)
    - [Approve-BHOperatorEULA](#approve-bhoperatoreula)
    - [Get-BHOperatorHelp](#get-bhoperatorhelp)
    - [Get-BHOperatorMFAStatus](#get-bhoperatormfastatus)
    - [Get-BHOperatorPermission](#get-bhoperatorpermission)
    - [Get-BHOperatorRole](#get-bhoperatorrole)
    - [Revoke-BHOperatorSecret](#revoke-bhoperatorsecret)
    - [Set-BHOperatorSecret](#set-bhoperatorsecret)
    - [Get-BHOperatorToken](#get-bhoperatortoken)
    - [New-BHOperatorToken](#new-bhoperatortoken)
    - [Revoke-BHOperatorToken](#revoke-bhoperatortoken)
- [BHData](#bhdata)
    - [Get-BHData](#get-bhdata)
    - [Start-BHDataAnalysis](#start-bhdataanalysis)
    - [Clear-BHDatabase](#clear-bhdatabase)
    - [Get-BHDataCollector](#get-bhdatacollector)
    - [Import-BHDataCollector](#import-bhdatacollector)
    - [Get-BHDataPosture](#get-bhdataposture)
    - [Read-BHDataSource](#read-bhdatasource)
    - [Get-BHDataUpload](#get-bhdataupload)
    - [Invoke-BHDataUpload](#invoke-bhdataupload)
    - [New-BHDataUpload](#new-bhdataupload)
- [BHNode](#bhnode)
    - [Format-BHNode](#format-bhnode)
    - [Get-BHNode](#get-bhnode)
    - [Search-BHNode](#search-bhnode)
    - [Remove-BHNodeFromNodeGroup](#remove-bhnodefromnodegroup)
    - [Get-BHNodeGroup](#get-bhnodegroup)
    - [New-BHNodeGroup](#new-bhnodegroup)
    - [Remove-BHNodeGroup](#remove-bhnodegroup)
    - [Set-BHNodeGroup](#set-bhnodegroup)
    - [Get-BHNodeMeta](#get-bhnodemeta)
    - [Add-BHNodeToNodeGroup](#add-bhnodetonodegroup)
- [BHPath](#bhpath)
    - [Get-BHPath](#get-bhpath)
    - [Get-BHPathComposition](#get-bhpathcomposition)
    - [Get-BHPathFilter](#get-bhpathfilter)
    - [Select-BHPathFilter](#select-bhpathfilter)
    - [Approve-BHPathFinding](#approve-bhpathfinding)
    - [Get-BHPathFinding](#get-bhpathfinding)
    - [Start-BHPathFinding](#start-bhpathfinding)
    - [Get-BHPathQuery](#get-bhpathquery)
    - [Invoke-BHPathQuery](#invoke-bhpathquery)
    - [New-BHPathQuery](#new-bhpathquery)
    - [Remove-BHPathQuery](#remove-bhpathquery)
    - [Set-BHPathQuery](#set-bhpathquery)
    - [Set-BHPathQueryPermission](#set-bhpathquerypermission)
- [BHClient](#bhclient)
    - [Get-BHClient](#get-bhclient)
    - [New-BHClient](#new-bhclient)
    - [Remove-BHClient](#remove-bhclient)
    - [Set-BHClient](#set-bhclient)
    - [Get-BHClientJob](#get-bhclientjob)
    - [Remove-BHClientJob](#remove-bhclientjob)
    - [Start-BHClientJob](#start-bhclientjob)
    - [New-BHClientToken](#new-bhclienttoken)
- [BHEvent](#bhevent)
    - [Get-BHEvent](#get-bhevent)
    - [New-BHEvent](#new-bhevent)
    - [Remove-BHEvent](#remove-bhevent)
    - [Set-BHEvent](#set-bhevent)

</br>


---

</br>

## **BHCOMPOSER**

### **Get-BHComposer**

Get BloodHound Composer

#### **Syntax:**

```PowerShell
Get-BHComposer [-ComposerFolder <Object>] 

Get-BHComposer -Composer [-ComposerFolder <Object>] 

Get-BHComposer -Env [-ComposerFolder <Object>] 

Get-BHComposer -Config [-ComposerFolder <Object>]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Get-BHComposer

```

See `Help Get-BHComposer` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Invoke-BHComposer**

**Alias**: `BHComposer`

Invoke BloodHound Composer

#### **Syntax:**

```PowerShell
Invoke-BHComposer [[-Action] <string>] [-ComposerFolder <string>] [-Force] 

Invoke-BHComposer -Command <string> [-ComposerFolder <string>]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Invoke-BHComposer Up

```

See `Help BHComposer` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **New-BHComposer**

New BloodHound Composer

#### **Syntax:**

```PowerShell
New-BHComposer [[-ComposerFolder] <string>] [-IncludeEnv] [-IncludeConfig]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > New-BHComposer $FolderLocation

```

See `Help New-BHComposer` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Get-BHComposerLog**

**Alias**: `BHLog`

Get BloodHound Composer Logs

#### **Syntax:**

```PowerShell
Get-BHComposerLog [-Limit <string>] [-ComposerFolder <Object>] 

Get-BHComposerLog -Trace [-Limit <string>] [-ComposerFolder <Object>] 

Get-BHComposerLog -TraceObject [-Limit <string>] [-ComposerFolder <Object>]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > BHLog -TraceObject | select time,status,message

```

See `Help BHLog` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

</br>

## **BHSESSION**

### **Get-BHSession**

**Alias**: `BHSession`

Get BloodHound API Session

#### **Syntax:**

```PowerShell
Get-BHSession [-Selected]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Get-BHSession


-------------------------- EXAMPLE 2 --------------------------

PS > Get-BHSession -Selected

```

See `Help BHSession` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **New-BHSession**

New BloodHound API Session

#### **Syntax:**

```PowerShell
New-BHSession [-JWT] <string> [-Server <string>] [-Port <string>] [-Protocol <string>] [-CypherClip] 

New-BHSession -TokenID <string> -Token <securestring> [-Server <string>] [-Port <string>] [-Protocol <string>] [-CypherClip]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > $TokenKey = Get-Clipboard | Convertto-SecureString -AsPlainText -Force

Convert plaintext token key from clipboard to secure string variable


-------------------------- EXAMPLE 2 --------------------------

PS > New-BHSession -TokenID $TokenID -Token $TokenKey

Create a BHCE session (localhost:8080).
- $TokenKey must be secure string.


-------------------------- EXAMPLE 3 --------------------------

PS > New-BHSession -Server $Instance -TokenID $TokenID -Token $TokenKey

Create a BHE session.
- $TokenKey must be secure string.


-------------------------- EXAMPLE 4 --------------------------

PS > New-BHSession -JWT $JWT [-Server $Instance]

Create Session with JWT

```

See `Help New-BHSession` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Remove-BHSession**

Remove BloodHound API Session

#### **Syntax:**

```PowerShell
Remove-BHSession [-ID] <int[]> [-Force]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Remove-BHSession

```

See `Help Remove-BHSession` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Select-BHSession**

**Alias**: `BHSelect`

Select BloodHound API Session

#### **Syntax:**

```PowerShell
Select-BHSession [-ID] <int[]> 

Select-BHSession -None
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Select-BHSession 1

```

See `Help BHSelect` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Set-BHSession**

Set BloodHound API Session

#### **Syntax:**

```PowerShell
Set-BHSession [[-Limit] <int>] [[-Timeout] <int>] [-CypherClip] [-NoClip]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Set-BHSession

```

See `Help Set-BHSession` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Invoke-BHSessionScript**

**Alias**: `BHScript`

Invoke BloodHound API Session Script

#### **Syntax:**

```PowerShell
Invoke-BHSessionScript [[-Script] <scriptblock>] [[-SessionID] <int[]>]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > BHScript {BHOperator -self | select principal_name} -SessionID 1,2

```

See `Help BHScript` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

</br>

## **BHAPI**

### **Get-BHAPI**

**Alias**: `BHAPIInfo`

Get BloodHound API Info

#### **Syntax:**

```PowerShell
Get-BHAPI
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Get-BHAPI


-------------------------- EXAMPLE 2 --------------------------

PS > Get-BHAPI | select-object method,route,summary | sort-object route

```

See `Help BHAPIInfo` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Invoke-BHAPI**

**Alias**: `BHAPI`

Invoke BloodHound API call

#### **Syntax:**

```PowerShell
Invoke-BHAPI [-URI] <string> [[-Method] <string>] [[-Body] <string>] [[-Filter] <string[]>] [[-SessionID] <int[]>] [[-Timeout] <int>] [[-Expand] <string>]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Invoke-BHAPI /api/version | Select-Object -ExpandProperty data | Select-Object -ExpandProperty server_version


-------------------------- EXAMPLE 2 --------------------------

PS > bhapi api/version -expand data.server_version


-------------------------- EXAMPLE 3 --------------------------

PS > BHAPI bloodhound-users POST $Json

```

See `Help BHAPI` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

</br>

## **BHSERVER**

### **Get-BHServerAuditLog**

**Alias**: `BHAudit`

Get BloodHound Server Audit Log

#### **Syntax:**

```PowerShell
Get-BHServerAuditLog [[-Limit] <string>] [[-Before] <datetime>] [[-After] <datetime>] [[-Filter] <string[]>] [[-Skip] <string>]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > BHAudit

```

See `Help BHAudit` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Get-BHServerConfig**

**Alias**: `BHConfig`

Get BloodHound Server Config

#### **Syntax:**

```PowerShell
Get-BHServerConfig
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > BHConfig

```

See `Help BHConfig` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Set-BHServerConfig**

**Alias**: `Set-BHConfig`

Set BloodHound Server Config

#### **Syntax:**

```PowerShell
Set-BHServerConfig [-ConfigKey] <string[]> [-Value] <hashtable>
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Set-BHConfig

```

See `Help Set-BHConfig` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Get-BHServerFeature**

**Alias**: `BHFeature`

Get BloodHound Server Feature

#### **Syntax:**

```PowerShell
Get-BHServerFeature
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > BHFeature

```

See `Help BHFeature` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Set-BHServerFeature**

**Alias**: `Set-BHFeature`

Set BloodHound Server Feature

#### **Syntax:**

```PowerShell
Set-BHServerFeature -FeatureID <int[]> -Enabled 

Set-BHServerFeature -FeatureID <int[]> -Disabled
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Set-BHFeature -id 1 -Enabled

```

See `Help Set-BHFeature` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Get-BHServerSAMLEndpoint**

**Alias**: `BHSAMLEndpoint`

Get BloodHound SAML Endpoints

#### **Syntax:**

```PowerShell
Get-BHServerSAMLEndpoint
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Get-BHServerSAMLEndpoint

```

See `Help BHSAMLEndpoint` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Get-BHServerSAMLProvider**

**Alias**: `BHSAMLProvider`

Get BloodHound SAML Provider

#### **Syntax:**

```PowerShell
Get-BHServerSAMLProvider [[-ProviderID] <int>]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Get-BHServerSAMLProvider

```

See `Help BHSAMLProvider` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **New-BHServerSAMLProvider**

**Alias**: `New-BHSAMLProvider`

New BloodHound SAML Provider

#### **Syntax:**

```PowerShell
New-BHServerSAMLProvider [-Name] <string> [-Metadata] <string>
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > New-BHServerSAMLProvider

```

See `Help New-BHSAMLProvider` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Remove-BHServerSAMLProvider**

**Alias**: `Remove-BHSAMLProvider`

Remove BloodHound SAML Provider

#### **Syntax:**

```PowerShell
Remove-BHServerSAMLProvider [-ProviderID] <int> [-Force] [-PassThru]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

Remove-BHServerSAMLProvider -id <id>[-Force]

```

See `Help Remove-BHSAMLProvider` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Get-BHServerVersion**

**Alias**: `BHVersion`

Get BloodHound Server version

#### **Syntax:**

```PowerShell
Get-BHServerVersion [[-SessionID] <int[]>]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > BHVersion

```

See `Help BHVersion` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

</br>

## **BHOPERATOR**

### **Disable-BHOperator**

Disable BloodHound Operator

#### **Syntax:**

```PowerShell
Disable-BHOperator [-OperatorID] <string[]> [-PassThru]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > BHOperator -id 2 | Disable-BHOperator

```

See `Help Disable-BHOperator` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Enable-BHOperator**

Enable BloodHound Operator

#### **Syntax:**

```PowerShell
Enable-BHOperator [-OperatorID] <string[]> [-PassThru]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > BHOperator -id 2 | Enable-BHOperator

```

See `Help Enable-BHOperator` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Get-BHOperator**

**Alias**: `BHOperator`

Get BloodHound Operator

#### **Syntax:**

```PowerShell
Get-BHOperator 

Get-BHOperator -ID <string[]> 

Get-BHOperator -Name <string[]> 

Get-BHOperator -Current 

Get-BHOperator -Role <string>
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > BHOperator

```

See `Help BHOperator` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **New-BHOperator**

New BloodHound Operator

#### **Syntax:**

```PowerShell
New-BHOperator [-Name] <string> [[-FirstName] <string>] [[-LastName] <string>] [[-Email] <string>] [[-Role] <int[]>] [-PassThru]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > New-BHOperator -name bob

```

See `Help New-BHOperator` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Remove-BHOperator**

Remove BloodHound Operator

#### **Syntax:**

```PowerShell
Remove-BHOperator [-OperatorID] <string[]> [-Force]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Remove-BHOperator

```

See `Help Remove-BHOperator` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Set-BHOperator**

Set BloodHound Operator

#### **Syntax:**

```PowerShell
Set-BHOperator [-OperatorID] <string> [[-Name] <string>] [[-FirstName] <string>] [[-LastName] <string>] [[-Email] <string>] [[-Role] <int[]>] [-PassThru]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > BHOperator -id 2 | Set-BHOperator -firstname alice

```

See `Help Set-BHOperator` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Approve-BHOperatorEULA**

[BHE] Approve BloodHound EULA

#### **Syntax:**

```PowerShell
Approve-BHOperatorEULA
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Approve-BHOperatorEULA

```

See `Help Approve-BHOperatorEULA` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Get-BHOperatorHelp**

**Alias**: `BHHelp`

Get BloodHound Operator Help

#### **Syntax:**

```PowerShell
Get-BHOperatorHelp [-ReadTheDocs] [-Online] 

Get-BHOperatorHelp [-TierZero] [-Online]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > BHHelp

```

See `Help BHHelp` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Get-BHOperatorMFAStatus**

**Alias**: `BHOperatorMFA`

Get BloodHound Operator MFA status

#### **Syntax:**

```PowerShell
Get-BHOperatorMFAStatus [-ID] <string[]>
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > BHOperator -self | Get-BHOperatorMFAStatus

```

See `Help BHOperatorMFA` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Get-BHOperatorPermission**

**Alias**: `BHPermission`

Get BloodHound Operator Permission

#### **Syntax:**

```PowerShell
Get-BHOperatorPermission [-Current]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > BHPermission

```

See `Help BHPermission` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Get-BHOperatorRole**

**Alias**: `BHRole`

Get BloodHound Operator Role

#### **Syntax:**

```PowerShell
Get-BHOperatorRole [-Current]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > BHRole

```

See `Help BHRole` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Revoke-BHOperatorSecret**

**Alias**: `Revoke-BHSecret`

Revoke BloodHound Operator Secret

#### **Syntax:**

```PowerShell
Revoke-BHOperatorSecret [-OperatorID] <string> [-Force]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Revoke-BHSecret

```

See `Help Revoke-BHSecret` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Set-BHOperatorSecret**

**Alias**: `Set-BHSecret`

Set BloodHound Operator Secret

#### **Syntax:**

```PowerShell
Set-BHOperatorSecret [-OperatorID] <string> [[-Secret] <string>] [-RequireReset] [-Force]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Set-BHSecret

```

See `Help Set-BHSecret` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Get-BHOperatorToken**

**Alias**: `BHToken`

Get BloodHound Operator Token

#### **Syntax:**

```PowerShell
Get-BHOperatorToken [[-Operator] <string[]>]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > BHToken

```

See `Help BHToken` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **New-BHOperatorToken**

**Alias**: `New-BHToken`

New BloodHound Operator Token

#### **Syntax:**

```PowerShell
New-BHOperatorToken [-OperatorID] <string> [[-TokenName] <string>] [-AsPlainText] [-Force]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > New-BHToken -ID $OperatorID -TokenName $TokenName

```

See `Help New-BHToken` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Revoke-BHOperatorToken**

**Alias**: `Revoke-BHToken`

Revoke BloodHound Operator Token

#### **Syntax:**

```PowerShell
Revoke-BHOperatorToken [[-TokenID] <string[]>] [-Force]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Revoke-BHToken

```

See `Help Revoke-BHToken` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

</br>

## **BHDATA**

### **Get-BHData**

**Alias**: `BHData`

Get BloodHound Data

#### **Syntax:**

```PowerShell
Get-BHData [[-ID] <string[]>] [-Limit <int>] [-Filter <string[]>] [-Expand <string>] 

Get-BHData -ListDomain [-Collected] [-Limit <int>] [-Filter <string[]>] [-Expand <string>] 

Get-BHData -Platform <string> [-Limit <int>] [-Filter <string[]>] [-Expand <string>] 

Get-BHData -PipeStatus [-Limit <int>] [-Filter <string[]>] [-Expand <string>]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > BHData -ListDomain


-------------------------- EXAMPLE 2 --------------------------

PS > BHData -Platform AD


-------------------------- EXAMPLE 3 --------------------------

PS > BHData -id $DomainID


-------------------------- EXAMPLE 4 --------------------------

PS > BHData

```

See `Help BHData` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Start-BHDataAnalysis**

**Alias**: `BHDataAnalysis`

Start BloodHound Data Analysis

#### **Syntax:**

```PowerShell
Start-BHDataAnalysis
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Start-BHDataAnalysis

```

See `Help BHDataAnalysis` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Clear-BHDatabase**

Clear BloodHound Database

#### **Syntax:**

```PowerShell
Clear-BHDatabase [-GraphData] [-IngestHistory] [-DataHistory] [-Force] [-Really]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Clear-BHDatabase -GraphData -Force -Really

```

See `Help Clear-BHDatabase` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Get-BHDataCollector**

**Alias**: `BHCollector`

Get BloodHound Data Collector

#### **Syntax:**

```PowerShell
Get-BHDataCollector [[-Collector] <string[]>]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Get-BHDataCollector

```

See `Help BHCollector` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Import-BHDataCollector**

**Alias**: `Import-BHCollector`

Import BloodHound Data Collector

#### **Syntax:**

```PowerShell
Import-BHDataCollector -SharpHound [-Version <string>] [-Unzip] 

Import-BHDataCollector -AzureHound [-Version <string>] [-Unzip]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Import-BHDataCollector -SharpHound

```

See `Help Import-BHCollector` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Get-BHDataPosture**

**Alias**: `BHPosture`

[BHE] Get BloodHound Data Posture

#### **Syntax:**

```PowerShell
Get-BHDataPosture [[-DomainID] <string[]>] [[-Limit] <int>]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Get-BHDataPosture

```

See `Help BHPosture` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Read-BHDataSource**

**Alias**: `BHRead`

Read BloodHound Data Source

#### **Syntax:**

```PowerShell
Read-BHDataSource [-Source] <string[]> [[-Split] <int>] [-Unpack]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Read-BHDataSource $Zip -Split 5000

```

See `Help BHRead` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Get-BHDataUpload**

**Alias**: `BHUpload`

Get BloodHound Data Upload

#### **Syntax:**

```PowerShell
Get-BHDataUpload [[-Expand] <string>] [[-Limit] <int>]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Get-BHDataUpload


-------------------------- EXAMPLE 2 --------------------------

PS > Get-BHDataUpload -limit 10

```

See `Help BHUpload` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Invoke-BHDataUpload**

**Alias**: `BHDataUpload`

Invoke BloodHound Data Upload

#### **Syntax:**

```PowerShell
Invoke-BHDataUpload [-Data] <string[]> [[-Split] <int>]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > BHDataUpload $Zip

```

See `Help BHDataUpload` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **New-BHDataUpload**

**Alias**: `BHDataUploadJSON`

New BloodHound Data Upload

#### **Syntax:**

```PowerShell
New-BHDataUpload [-UploadJSON] <string[]>
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > BHDataUploadJSON $JSON

```

See `Help BHDataUploadJSON` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

</br>

## **BHNODE**

### **Format-BHNode**

**Alias**: `BHFormat`

Format BloodHound Node

#### **Syntax:**

```PowerShell
Format-BHNode [-Object] <psobject> [-PropOnly]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > BHFormat

```

See `Help BHFormat` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Get-BHNode**

**Alias**: `BHNode`

Get BloodHound Node

#### **Syntax:**

```PowerShell
Get-BHNode [[-List] <string>] [-ObjectID] <string[]> [-PropOnly] [-Expand <string>] [-AsPath] [-Limit <int>] [-Cypher] [-SessionID <int[]>] 

Get-BHNode [[-List] <string>] [[-Keyword] <string[]>] -Search [-PropOnly] [-Expand <string>] [-AsPath] [-Limit <int>] [-Cypher] [-SessionID <int[]>]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

BHNode User -id <id>


-------------------------- EXAMPLE 2 --------------------------

PS > BHNode -Search User alice


-------------------------- EXAMPLE 3 --------------------------

PS > bhnode -search user yoda -list controllers


-------------------------- EXAMPLE 4 --------------------------

PS > bhnode -search user yoda -list controllers -AsPath [-Cypher] # EXPERIMENTAL - DO NOT TRUST OUTPUT

```

See `Help BHNode` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Search-BHNode**

**Alias**: `BHSearch`

Search BloodHound Node

#### **Syntax:**

```PowerShell
Search-BHNode [[-Label] <BHEntityType[]>] [[-Keyword] <string[]>] [-Limit <int>] [-Exact] [-SessionID <int[]>]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > BHSearch user bob

```

See `Help BHSearch` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Remove-BHNodeFromNodeGroup**

Remove BHNode From BHNodeGroup

#### **Syntax:**

```PowerShell
Remove-BHNodeFromNodeGroup [-ObjectID] <string[]> [-NodeGroupID] <int[]> [-Analyse] [-Force]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > BHSearch User alice | Remove-BHNodeFromNodeGroup -NodeGroupID 1

```

See `Help Remove-BHNodeFromNodeGroup` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Get-BHNodeGroup**

**Alias**: `BHNodeGroup`

Get BloodHound Asset Group

#### **Syntax:**

```PowerShell
Get-BHNodeGroup [[-ID] <string[]>] [-Selector] 

Get-BHNodeGroup [-ID] <string[]> -Member [-EnvironmentID <string>] [-Count] 

Get-BHNodeGroup [-ID] <string[]> 

Get-BHNodeGroup [-ID] <string[]> -CustomCount
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > BHNodeGroup

```

See `Help BHNodeGroup` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **New-BHNodeGroup**

New BloodHound Asset Group

#### **Syntax:**

```PowerShell
New-BHNodeGroup [-Name] <string> [[-Tag] <string>] [-PassThru]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > New-BHNodeGroup TestGroup

```

See `Help New-BHNodeGroup` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Remove-BHNodeGroup**

Remove BloodHound Asset Group

#### **Syntax:**

```PowerShell
Remove-BHNodeGroup [-ID] <int[]> [-Force]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Remove-BHNodeGroup 2

```

See `Help Remove-BHNodeGroup` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Set-BHNodeGroup**

Set BloodHound Asset Group

#### **Syntax:**

```PowerShell
Set-BHNodeGroup [-ID] <int> [-Name] <string>
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Set-BHNodeGroup -ID $GroupID -Name $NewName

```

See `Help Set-BHNodeGroup` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Get-BHNodeMeta**

**Alias**: `BHMeta`

[BHE] Get BloodHound Entity Meta

#### **Syntax:**

```PowerShell
Get-BHNodeMeta [-ID] <string[]>
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

BHMeta <objectID>

```

See `Help BHMeta` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Add-BHNodeToNodeGroup**

Add BHNode To BHNodeGroup

#### **Syntax:**

```PowerShell
Add-BHNodeToNodeGroup [-ObjectID] <string[]> [-NodeGroupID] <int> [-Analyze] [-Force]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > BHSearch User alice | Add-BHNodeToNodeGroup -NodeGroupID 1

```

See `Help Add-BHNodeToNodeGroup` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

</br>

## **BHPATH**

### **Get-BHPath**

**Alias**: `BHCypher`

Get BloodHound Path

#### **Syntax:**

```PowerShell
Get-BHPath [-Query] <string> [-Cypher] [-NoConvert] [-Minimal] [-Expand <string>] 

Get-BHPath -TargetID <string[]> [-All] [-Shortest] [-SourceID <string[]>] [-Edge <string[]>] [-Hop <string>] [-SourceWhere <string>] [-TargetWhere <string>] [-PathWhere <string>] [-Return <string>] [-OrderBy <string>] [-Limit <int>] [-Cypher] [-NoConvert] [-Minimal] [-Expand <string>] 

Get-BHPath [-All] [-Shortest] [-Source <string>] [-Target <string>] [-Edge <string[]>] [-Hop <string>] [-SourceWhere <string>] [-TargetWhere <string>] [-PathWhere <string>] [-Return <string>] [-OrderBy <string>] [-Limit <int>] [-Cypher] [-NoConvert] [-Minimal] [-Expand <string>]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > BHPath

```

See `Help BHCypher` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Get-BHPathComposition**

**Alias**: `BHComposition`

Get BloodHound Path Composition

#### **Syntax:**

```PowerShell
Get-BHPathComposition [-SourceID] <string> [-TargetID] <string> [-EdgeType] <string>
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Get-BHPathComposition -SourceID $x -EdgeType $r -TargetID $y


-------------------------- EXAMPLE 2 --------------------------

BHPath "MATCH p=(:User{name:'$UserName'})-[:ADCSESC1]->(:Domain) RETURN p" | BHComposition | ft

```

See `Help BHComposition` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Get-BHPathFilter**

**Alias**: `BHFilter`

Get BloodHound Path Filter

#### **Syntax:**

```PowerShell
Get-BHPathFilter [-String] [-Cypher] 

Get-BHPathFilter -ListAll
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > BHFilter

```

See `Help BHFilter` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Select-BHPathFilter**

**Alias**: `BHFilterSelect`

Select BloodHound Path Filter

#### **Syntax:**

```PowerShell
Select-BHPathFilter -All 

Select-BHPathFilter -None 

Select-BHPathFilter -Platform <BHPlatform[]> [-NoSelect] 

Select-BHPathFilter -EdgeGroup <BHEdgeGroup[]> [-NoSelect] 

Select-BHPathFilter -Edge <BHEdge[]> [-NoSelect]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Select-BHFilter

```

See `Help BHFilterSelect` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Approve-BHPathFinding**

**Alias**: `Approve-BHFinding`

[BHE] Approve BloodHound Path Finding

#### **Syntax:**

```PowerShell
Approve-BHPathFinding [-ID] <int[]> [-FindingType] <BHFindingType> [-Accepted] <bool> [[-Until] <datetime>] [-Force] [-PassThru]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Approve-BHPathFinding -ID $id [-Force]

```

See `Help Approve-BHFinding` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Get-BHPathFinding**

**Alias**: `BHFinding`

[BHE] Get BloodHound Path Finding

#### **Syntax:**

```PowerShell
Get-BHPathFinding [-TypeList] 

Get-BHPathFinding [-DomainID] <string[]> -ListAvail 

Get-BHPathFinding [-DomainID] <string[]> -Detail [-FindingType <BHFindingType[]>] [-Limit <int>] 

Get-BHPathFinding [-DomainID] <string[]> -Sparkline [-FindingType <BHFindingType[]>] [-StartDate <datetime>] [-EndDate <datetime>] [-Limit <int>]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > BHFinding -TypeList


-------------------------- EXAMPLE 2 --------------------------

PS > BHFinding -ListAvail -DomainID $ID


-------------------------- EXAMPLE 3 --------------------------

PS > BHFinding -Detail -DomainID $ID -Type Kerberoasting

```

See `Help BHFinding` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Start-BHPathFinding**

**Alias**: `BHPathAnalysis`

[BHE] Start BloodHound Path Finding

#### **Syntax:**

```PowerShell
Start-BHPathFinding
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Start-BHPathFinding

```

See `Help BHPathAnalysis` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Get-BHPathQuery**

**Alias**: `BHQuery`

Get BloodHound Query

#### **Syntax:**

```PowerShell
Get-BHPathQuery [[-ID] <string[]>] [-Expand <string>] 

Get-BHPathQuery -Name <string[]> [-Expand <string>] 

Get-BHPathQuery -Scope <string> [-Expand <string>] 

Get-BHPathQuery -Description <string[]> [-Expand <string>]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > BHQuery


-------------------------- EXAMPLE 2 --------------------------

PS > BHQuery -ID 123


-------------------------- EXAMPLE 3 --------------------------

PS > BHQuery -name MyQuery


-------------------------- EXAMPLE 4 --------------------------

BHQuery -description <keyword>


-------------------------- EXAMPLE 5 --------------------------

BHQuery -scope <shared|public>

```

See `Help BHQuery` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Invoke-BHPathQuery**

**Alias**: `BHInvoke`

Invoke BloodHound Query

#### **Syntax:**

```PowerShell
Invoke-BHPathQuery [-Query] <string> [[-Description] <string>] [[-Name] <string>] [[-ID] <string>] [[-Expand] <string>] [[-Select] <string[]>] [-Minimal]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Invoke-BHQuery "MATCH (x:User) RETURN x LIMIT 1"


-------------------------- EXAMPLE 2 --------------------------

PS > Invoke-BHQuery "api/version"


-------------------------- EXAMPLE 3 --------------------------

PS > BHQuery -ID 123 | BHInvoke

```

See `Help BHInvoke` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **New-BHPathQuery**

**Alias**: `New-BHQuery`

New BloodHound Query

#### **Syntax:**

```PowerShell
New-BHPathQuery [-Name] <string> [[-Description] <string>] [-Query] <string> [-PassThru]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > New-BHPathQuery -Name MySavedQuery -Query "MATCH (x:User) RETURN x LIMIT 1" -Desc "My Saved Query"

```

See `Help New-BHQuery` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Remove-BHPathQuery**

**Alias**: `Remove-BHQuery`

Remove BloodHound Saved Query

#### **Syntax:**

```PowerShell
Remove-BHPathQuery [-ID] <string> [-Force]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

Remove-BHPathQuery -id <QueryID>-Force

```

See `Help Remove-BHQuery` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Set-BHPathQuery**

**Alias**: `Set-BHQuery`

Set BloodHound Query

#### **Syntax:**

```PowerShell
Set-BHPathQuery [-ID] <int> [[-Name] <string>] [[-Query] <string>] [[-Description] <string>]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Set-BHPathQuery -ID 123 -Name MySavedQuery

```

See `Help Set-BHQuery` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Set-BHPathQueryPermission**

**Alias**: `Set-BHQueryPermission`

Set BloodHound Query Permissions

#### **Syntax:**

```PowerShell
Set-BHPathQueryPermission [-ID] <int> -Public 

Set-BHPathQueryPermission [-ID] <int> -Private 

Set-BHPathQueryPermission [-ID] <int> -Share <string[]> [-Remove]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Set-BHQueryPermission -ID 123 -Public


-------------------------- EXAMPLE 2 --------------------------

PS > Set-BHQueryPermission -ID 123 -Private


-------------------------- EXAMPLE 3 --------------------------

Set-BHQueryPermission -ID 123 -Share <UserID[]>


-------------------------- EXAMPLE 4 --------------------------

Set-BHQueryPermission -ID 123 -Share <UserID[]>-Remove

```

See `Help Set-BHQueryPermission` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

</br>

## **BHCLIENT**

### **Get-BHClient**

**Alias**: `BHClient`

[BHE] Get BloodHound Client

#### **Syntax:**

```PowerShell
Get-BHClient 

Get-BHClient -ID <string[]> [-CompletedJobs]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Get-BHClient -ID $ClientID


-------------------------- EXAMPLE 2 --------------------------

PS > Get-BHClient -ID $ClientID -CompletedJobs

```

See `Help BHClient` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **New-BHClient**

[BHE] New BloodHound Client

#### **Syntax:**

```PowerShell
New-BHClient [-Name] <string[]> [-ClientType] <string> [[-DomainController] <string>]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > $Client = @{
Prop = value
}
New-BHClient @Client

```

See `Help New-BHClient` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Remove-BHClient**

[BHE] Remove-BloodHound Client

#### **Syntax:**

```PowerShell
Remove-BHClient [-ID] <string> [-Force]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Example

```

See `Help Remove-BHClient` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Set-BHClient**

[BHE] Set BloodHound Client

#### **Syntax:**

```PowerShell
Set-BHClient [-ID] <string> [[-Name] <string>] [[-DomainController] <string>]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Example

```

See `Help Set-BHClient` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Get-BHClientJob**

**Alias**: `BHJob`

[BHE] Get BloodHound Client Job

#### **Syntax:**

```PowerShell
Get-BHClientJob [-ClientID <string[]>] [-Status <int>] [-Limit <int>] 

Get-BHClientJob -IncludeUnfinished [-ClientID <string[]>] [-Status <int>] [-Only] 

Get-BHClientJob -JobID <string> [-Logs]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

Get-BHClientJob [-status <status>] [-ClientID <client_id>]


-------------------------- EXAMPLE 2 --------------------------

PS > BHJob -IncludeUnfinished [-Only]


-------------------------- EXAMPLE 3 --------------------------

PS > BHJob -JobId 1234 [-log]

```

See `Help BHJob` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Remove-BHClientJob**

**Alias**: `Remove-BHJob`

[BHE] Remove BloodHound Client Job

#### **Syntax:**

```PowerShell
Remove-BHClientJob [-ID] <string> [-Force]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Remove-BHClientJob -Id $JobId

```

See `Help Remove-BHJob` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Start-BHClientJob**

**Alias**: `Start-BHJob`

[BHE] Start BloodHound Client Job

#### **Syntax:**

```PowerShell
Start-BHClientJob [-ClientID] <string[]> [[-OU] <string[]>] [[-Domain] <string[]>] [-SessionCollection] [-LocalGroupCollection] [-ADStructureCollection] [-CertServiceCollection] [-CARegistryCollection] [-DCRegistryCollection] [-AllDomain] [-Force]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Start-BHClientJob

```

See `Help Start-BHJob` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **New-BHClientToken**

[BHE] New BloodHound Client Token

#### **Syntax:**

```PowerShell
New-BHClientToken [-ID] <string[]> [-AsPlainText] [-Force]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > New-BHClientToken -id $ClientID [-Force]

```

See `Help New-BHClientToken` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

</br>

## **BHEVENT**

### **Get-BHEvent**

[BHE] Get BloodHound Client Event

#### **Syntax:**

```PowerShell
Get-BHEvent -EventID <string[]> 

Get-BHEvent [-ClientID <string[]>]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Get-BHEvent

```

See `Help Get-BHEvent` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **New-BHEvent**

[BHE] New BloodHound Client Event

#### **Syntax:**

```PowerShell
New-BHEvent [[-ClientID] <string[]>] [[-Rule] <string>] [[-OU] <string[]>] [[-Domain] <string[]>] [-SessionCollection] [-LocalGroupCollection] [-ADStructureCollection] [-CertServiceCollection] [-CARegistryCollection] [-DCRegistryCollection] [-AllDomain]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > New-BHEvent

```

See `Help New-BHEvent` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Remove-BHEvent**

[BHE] Remove BloodHound Client Event

#### **Syntax:**

```PowerShell
Remove-BHEvent [-ID] <string> [-Force]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Remove-BHEvent $EventID

```

See `Help Remove-BHEvent` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

### **Set-BHEvent**

[BHE] Set BloodHound Client Event

#### **Syntax:**

```PowerShell
Set-BHEvent [-ID] <string[]> [[-Rule] <string>] [[-SessionCollection] <bool>] [[-LocalGroupCollection] <bool>] [[-ADStructureCollection] <bool>] [[-CertServiceCollection] <bool>] [[-CARegistryCollection] <bool>] [[-DCRegistryCollection] <bool>] [[-AllDomain] <bool>] [[-OU] <string[]>] [[-Domain] <string[]>] [-PassThru]
```

#### **Examples:**

```PowerShell
-------------------------- EXAMPLE 1 --------------------------

PS > Set-BHEvent

```

See `Help Set-BHEvent` for more info

</br>

</br>


[BackToTop](#table-of-content)


</br>

---

</br>

Tuesday, September 17, 2024 12:07:30 PM


