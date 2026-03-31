## BloodHoundOperator - Full ##
# Tuesday, March 31, 2026 2:02:36 PM
############################################################

## BloodHound Operator - BHComposer (BHCE Only)
# New-BHComposer
# Invoke-BHComposer
# Get-BHComposer
# Get-BHComposerLog


# Other "outside" callers
# Get-BHOperatorHelp
# Import-BHDataCollector
# Get-BHPathQueryOnlineLibrary




################################################ New-BHComposer

<#
.SYNOPSIS
New BloodHound Composer
.DESCRIPTION
Download BloodHound docker-compose files
.EXAMPLE
New-BHComposer $FolderLocation
#>
function New-BHComposer{
    Param(
        [Parameter(Mandatory=0)][String]$ComposerFolder=$pwd,
        [Parameter(Mandatory=0)][Switch]$IncludeEnv,
        [Parameter(Mandatory=0)][Switch]$IncludeConfig
        )
    if(-Not(Test-Path $ComposerFolder)){$Null = mkdir $ComposerFolder}
    # Docker Compose
    irm https://ghst.ly/getbhce | out-file "$ComposerFolder/docker-compose.yml"
    # Docker env
    if($IncludeEnv){
        irm https://raw.githubusercontent.com/SpecterOps/BloodHound/main/examples/docker-compose/.env.example | out-file "$ComposerFolder/.env.example"
        }
    # BH Config
    if($IncludeConfig){
        irm https://raw.githubusercontent.com/SpecterOps/BloodHound/main/examples/docker-compose/bloodhound.config.json | out-file "$ComposerFolder/bloodhound.config.json"
        }}
#####End


################################################ Invoke-BHComposer

<#
.SYNOPSIS
Invoke BloodHound Composer
.DESCRIPTION
Invoke BloodHound docker-compose commands
.EXAMPLE
Invoke-BHComposer Up
#>
function Invoke-BHComposer{
    [Alias('BHComposer')]
    Param(
        [ValidateSet('Status','Up','Start','Pause','Resume','Stop','Down','Update','KillNeo','KillAll')]
        [Parameter(Mandatory=0,Position=0,ParameterSetName='Action')][String]$Action='Status',
        [Parameter(Mandatory=1,ParameterSetName='Command')][String]$Command,
        [Parameter(Mandatory=0)][String]$ComposerFolder=$pwd,
        [Parameter(Mandatory=0,ParameterSetName='Action')][Switch]$Force
        )
    # Action
    if($PSCmdlet.ParameterSetName -eq 'Action'){
        $Project = split-path $ComposerFolder -leaf
        Switch($Action){
            Status {docker compose $Composer ps --format json | Convertfrom-JSON}
            Up     {docker compose $Composer up}
            Start  {docker compose $Composer start}
            Pause  {docker compose $Composer pause}
            Resume {docker compose $Composer unpause}
            Stop   {docker compose $Composer stop}
            Down   {if($Force -OR $(Confirm-Action "Remove $Project [Keep volumes]")){
                docker compose $Composer down
                }}
            Update {if($Force -OR $(Confirm-Action "Update $Project to latest build - Keep volumes")){
                docker compose $Composer down
                docker compose $Composer pull
                docker compose $Composer up
                }}
            KillNeo{if($Force -OR $(Confirm-Action "Remove $Project - Neo4j data only")){
                $Project= $Project.ToLower()
                docker volume rm ${Project}_neo4j-data
                }}
            KillAll{if($Force -OR $(Confirm-Action "Remove $Project - Remove volumes")){
                docker compose $Composer down -v
                }}}}
    # Command ##
    else{docker compose $Composer $Command}
    }
#End


################################################ Get-BHComposer

<#
.SYNOPSIS
    Get BloodHound Composer
.DESCRIPTION
    View Composer status
    View BloodHound docker-compose files content
.EXAMPLE
    Get-BHComposer
#>
Function Get-BHComposer{
    [CmdletBinding(DefaultParameterSetName='status')]
    Param(
        [Parameter(Mandatory=1,ParameterSetName='Composer')][Switch]$Composer,
        [Parameter(Mandatory=1,ParameterSetName='Env')][Switch]$Env,
        [Parameter(Mandatory=1,ParameterSetName='Config')][Switch]$Config,
        [Parameter(Mandatory=0)]$ComposerFolder=$pwd
        )
    Switch($PSCmdlet.ParameterSetName){
        status   {docker compose ps --format json | Convertfrom-JSON}
        Composer {get-content $ComposerFolder/docker-compose.yml}
        env      {get-content $ComposerFolder/.env}
        Config   {get-content $ComposerFolder/bloodhound.config}
        }}
#####End


################################################ Get-BHComposerLog

<#
.SYNOPSIS
    Get BloodHound Composer Logs
.DESCRIPTION
    Get BloodHound Composer Logs
.EXAMPLE
    BHLog -TraceObject | select time,status,message
#>
Function Get-BHComposerLog{
    [Alias('BHLog')]
    [CmdletBinding(DefaultParameterSetName='obj')]
    Param(
        [Parameter(Mandatory=0)][Alias('Latest')][string]$Limit='all',
        [Parameter(Mandatory=1,ParameterSetName='Trace')][Switch]$Trace,
        [Parameter(Mandatory=1,ParameterSetName='TraceObject')][Switch]$TraceObject,
        [Parameter(Mandatory=0)]$ComposerFolder=$pwd
        )
    Switch($PSCmdlet.ParameterSetName){
        TraceObject{$Ago = [DateTime]::utcnow.ToString('o')
            while($true){
                docker compose logs --since $Ago --no-log-prefix bloodhound | Convertfrom-JSON | sort-object time -descending
                $Ago = [DateTime]::utcnow.ToString('o')
                Start-Sleep -seconds 1
                }}
        Trace   {docker compose logs -f bloodhound}
        Default {docker compose logs -n $Limit --no-log-prefix bloodhound | Convertfrom-JSON}
        }}
#####End

###################################################################################

## Stuff moved here so I can exclude from "muted" release

################################################ Get-BHOperatorHelp

<#
.Synopsis
    Get BloodHound Operator Help
.DESCRIPTION
    Get BloodHound Operator Help
.EXAMPLE
    BHHelp
#>
function Get-BHOperatorHelp{
    [CmdletBinding(DefaultParameterSetName='BH')]
    [Alias('BHHelp')]
    Param(
        [Parameter(Mandatory=0,ParameterSetName='BH')][Switch]$ReadTheDocs,
        [Parameter(ParameterSetName='T0')][Switch]$TierZero,
        [Parameter()][Switch]$Online
        )
    if($ReadTheDocs){Start-Process 'https://support.bloodhoundenterprise.io/hc/en-us/categories/1260801932169-General'}
    elseif($Online){
        if($TierZero){Start-Process 'https://specterops.github.io/TierZeroTable/'}
        else{Start-Process 'https://gist.github.com/SadProcessor/f996c01b57e1f11c67f91de2070d45fe'}
        }
    else{if($TierZero){
        $TZ = irm 'https://raw.githubusercontent.com/SpecterOps/TierZeroTable/main/TierZeroTable.csv' | ConvertFrom-Csv -Delimiter ';'
        $TZ | %{[PSCustomObject]@{
            Provider = Switch($_.IdP){'Active Directory'{'AD'}Default{$_}}
            Type = $_.Type
            Name = $_.name
            Identifier = $_.Identification
            IsTierZero  = Switch($_.'Is Tier Zero'){NO{$False}YES{$true}Default{$_}}
            Description = $_.Description
            Reasoning = $_.Reasoning
            CanCompromise          = if($_.'Known Tier Zero compromise by common (mis)configuration'-match"^YES" -OR $_.'Known Tier Zero compromise by default configuration'-match"^YES"){$true}else{'??'}
            DefaultConfig          = if($_.'Known Tier Zero compromise by common (mis)configuration'-match"^YES" -OR $_.'Known Tier Zero compromise by default configuration'-match"^YES"){if($_.'Known Tier Zero compromise by default configuration'-match"^YES"){$true}else{$false}}else{}
            CompromiseType         = $(if($_.'Known Tier Zero compromise by common (mis)configuration'-match"^YES"){
                                        $_.'Known Tier Zero compromise by common (mis)configuration'.split('-')[1].trim()
                                        }
                                     elseif($_.'Known Tier Zero compromise by default configuration'-match"^YES"){
                                        $_.'Known Tier Zero compromise by default configuration'.split('-')[1].trim()
                                        })
            IsAdminSDHolder  = Switch($_.'AdminSDHolder protected'){NO{$False}YES{$true}}
            IsPrivAccessRole = Switch($_.'Microsoft: Privileged access security roles'){NO{$False}YES{$true}}
            Links = ($_.'External Links'-split("`r`n")).trim()
            }}
        }
        else{$CmdletList = @(
            Get-Command *-BHComposer*   | sort-object Noun,Verb
            Get-Command *-BHSession*    | sort-object Noun,Verb
            Get-Command *-BHAPI*        | sort-object Noun,Verb
            Get-Command *-BHServer*     | sort-object Noun,Verb
            Get-Command *-BHOperator*   | sort-object Noun,Verb
            Get-Command *-BHData*       | sort-object Noun,Verb
            Get-Command *-BHNode*       | sort-object Noun,Verb
            Get-Command *-BHPath*       | sort-object Noun,Verb
            Get-Command *-BHClient*     | sort-object Noun,Verb
            Get-Command *-BHEvent*      | sort-object Noun,Verb
            Get-Command *-BHRRule*      | sort-object Noun,Verb
            Get-Command *-BHDate*       | sort-object Noun,Verb
            Get-Command *-BHAssetGroup* | sort-object Noun,Verb
            Get-Command *-BHOpenGraph*  | sort-object Noun,Verb
            )
        $Out = Foreach($Cmdlet in $CmdletList){
            $Als = Get-Alias -Definition $Cmdlet.name -ea 0 | Select -first 1
            [PSCustomObject]@{
                Cmdlet   = $Cmdlet.Name
                Alias    = $Als
                Description = (Get-Help $Cmdlet.Name).synopsis
                Examples = "Help $(if($Als){$Als}else{$Cmdlet.Name}) -Example"
                }}
        if($BHCE){$Out|? description -notmatch "^\[BHE\]"}else{$Out}
        }}}
#####End


#################################################

################################################ Import-BHDataCollector

<#
.Synopsis
    Import BloodHound Data Collector
.DESCRIPTION
    Import BloodHound Data Collector
    /!\ AV
.EXAMPLE
    Import-BHDataCollector -SharpHound
#>
function Import-BHDataCollector{
    [Alias('Import-BHCollector')]
    Param(
        [Parameter(Mandatory=1,ParameterSetName='SharpHound')][Switch]$SharpHound,
        [Parameter(Mandatory=1,ParameterSetName='AzureHound')][Switch]$AzureHound,
        [Parameter(Mandatory=0)][string]$Version,
        [Parameter(Mandatory=0)][Switch]$Unzip
        )
    if(-Not$Version){$Version=(Get-BHDataCollector $PSCmdlet.ParameterSetName).latest}
    $Download = Switch($PSCmdlet.ParameterSetName){
        AzureHound{
            "https://github.com/BloodHoundAD/AzureHound/releases/download/$Version/azurehound-windows-amd64.zip"
            }
        SharpHound{
            "https://github.com/BloodHoundAD/SharpHound/releases/download/$Version/SharpHound-$Version.zip"
            }
        }
    Start-BitsTransfer -source $Download
    if($Unzip){Expand-Archive $(Split-Path $Download -leaf)}
    }
#End


###################################################################


<#
.SYNOPSIS
    Get BloodHound Query
.DESCRIPTION
    Get BloodHound Saved Query 
.EXAMPLE
    BHQuery
.EXAMPLE
    BHQuery -ID 123
.EXAMPLE
    BHQuery -name MyQuery
.EXAMPLE
    BHQuery -description <keyword>
.EXAMPLE
    BHQuery -scope <shared|public>
#>
function Get-BHPathQueryOnlineLibrary{
    [CmdletBinding(DefaultParameterSetName='ByID')]
    [Alias('BHQLib','Get-BHQueryLibrary')]
    Param()
    irm https://raw.githubusercontent.com/SpecterOps/BloodHoundQueryLibrary/refs/heads/main/Queries.json | sort name -unique
    }
#End

## BloodHound Operator - BHAPI
# Get-BHAPI
# Invoke-BHAPI


################################################ Get-BHAPI

<#
.Synopsis
    Get BloodHound API Info
.DESCRIPTION
    Return BloodHound API Info as objects
.EXAMPLE
    Get-BHAPI
.EXAMPLE
    Get-BHAPI | select-object method,route,summary | sort-object route
#>
Function Get-BHAPI{
    [Alias('BHAPIInfo')]
    Param()
    foreach ($APIObj in (invoke-BHAPI "api/v2/swagger/doc.json").paths){
        foreach($Route in ($APIObj | GM | ? MemberType -eq NoteProperty).name){
            foreach($Meth in (($APIObj.$Route | gm | ? Membertype -eq Noteproperty).name | ?{$_ -ne 'parameters'})){
                $RouteData   = $APIObj.$Route.$Meth
                [PSCustomObject]@{
                    Route       = $Route
                    Method      = $Meth
                    Deprecated  = $RouteData.Deprecated
                    Tag         = $RouteData.tags
                    Data        = $RouteData
                    Summary     = $RouteData.Summary
                    Description = $RouteData.description
                    Parameters  = $RouteData.parameters
                    Consumes    = $RouteData.consumes
                    ParamInfo   = $APIObj.$Route.Parameters
                    }}}}}
#################End



################################################ Invoke-BHAPI

<#
function Invoke-BHAPI{
    [Alias('BHAPI')]
    param(
        # URI
        [Parameter(Mandatory=1)][String]$URI,
        # Method
        [ValidateSet('GET','POST','PATCH','PUT','DELETE')]
        [Parameter(Mandatory=0)][String]$Method='GET',
        # Body
        [Parameter(Mandatory=0)][String]$Body,
        # Session
        [Parameter(Mandatory=0)][int[]]$SessionID=($BHSession | ? x).id,
        # Timeout
        [Parameter(Mandatory=0)][Alias('Prefer')][int]$Timeout,
        # Expand
        [Parameter(Mandatory=0)][Alias('Dot')][String]$Expand
        )
    begin{
        if(-Not$SessionID){Write-Warning "No BHSession: Use New-BHSession or Select-BHSession";Break}
        if($URI -match "^/"){$URI=$URI.trimstart('/')}
        if($URI -notmatch "^api/"){$URI='api/v2/'+$URI}
        }
    process{foreach($SessID in $SessionID){
            # Session
            $Session   = $BHSession | ? ID -eq $SessID
            $Proto     = $Session.Protocol
            $Server    = $Session.Server
            $Port      = $Session.Port
            $TokenID   = $Session.TokenID
            $TokenKey  = $Session.Token | Read-SecureString
            if(-Not$TimeOut){$Timeout=($BHSession | ? id -eq $SessID).timeout}
            # Signature
            $Timestamp = [Datetime]::utcnow.tostring('o')
            $KeyByte   = [Text.Encoding]::UTF8.GetBytes($TokenKey)
            $OpByte    = [Text.Encoding]::UTF8.GetBytes("$Method/$URI")
            $DateByte  = [Text.Encoding]::UTF8.GetBytes(-join $Timestamp[0..12])
            $BodyByte  = [Text.Encoding]::UTF8.GetBytes("$Body")
            $HMAC      = [Security.Cryptography.HMACSHA256]::new($KeyByte).ComputeHash($OpByte)
            $HMAC      = [Security.Cryptography.HMACSHA256]::new($HMAC).ComputeHash($DateByte)
            $HMAC      = [Security.Cryptography.HMACSHA256]::new($HMAC).ComputeHash($BodyByte)
            $Sign      = [Convert]::ToBase64String($HMAC)
            # Headers
            $Headers = @{
                Authorization = "BHESignature $TokenID"
                Signature     = $Sign
                RequestDate   = $Timestamp
                }
            if($Timeout){$Headers.add('Prefer',$Timeout)}
            # Verbose
            Write-verbose "[BH] $Method $URI"
            if($Body){Write-Verbose "$Body"}
            # Params
            if($Port){$Server="${server}:${Port}"}
            $Params = @{
                Uri         = "${Proto}://${Server}/${URI}"
                ContentType = 'application/json'
                Method      = $Method
                Headers     = $Headers
                UserAgent   = 'PowerShell BloodHound Operator'
                }
            #Write-Verbose $Params.Uri
            # Body
            #if($Method -eq 'POST' -AND $uri -match 'api/v2/saml/providers'){$Param['ContentType']='multipart/form'}
            if($Body){$Params.Add('Body',"$Body")}
            # Call
            try{$Reply = Invoke-RestMethod @Params -verbose:$false -UseBasicParsing}catch{Get-ErrorWarning;Break}
            # Output
            if($Expand){foreach($Dot in $Expand.split('.')){try{$Reply=$Reply.$Dot}Catch{}}}
            $Reply
            }}
    end{}###
    }
#End
#>


<#
function Invoke-BHAPI{
    [Alias('BHAPI')]
    param(
        # URI
        [Parameter(Mandatory=1)][String]$URI,
        # Method
        [ValidateSet('GET','POST','PATCH','PUT','DELETE')]
        [Parameter(Mandatory=0)][String]$Method='GET',
        # Body
        [Parameter(Mandatory=0)][String]$Body,
        # FIlters
        [Parameter(Mandatory=0)][String[]]$Filter,
        # Session
        [Parameter(Mandatory=0)][int[]]$SessionID=($BHSession | ? x).id,
        # Timeout
        [Parameter(Mandatory=0)][Alias('Prefer')][int]$Timeout,
        # Expand
        [Parameter(Mandatory=0)][Alias('Dot')][String]$Expand
        )
    begin{
        if(-Not$SessionID){Write-Warning "No BHSession found: Use New-BHSession [Help New-BHSession]";Break}
        if($URI -match "^/"){$URI=$URI.trimstart('/')}
        if($URI -notmatch "^api/"){$URI='api/v2/'+$URI}
        if($filter){$qFilter = '?'+$($Filter.replace(' ','+')-join'&')
            $qfilter=[uri]::EscapeUriString($qFilter)
            $URI=$URI+$qfilter
            }
        }
    process{foreach($SessID in $SessionID){
            # Session
            $Session   = $BHSession | ? ID -eq $SessID
            $Proto     = $Session.Protocol
            $Server    = $Session.Server
            $Port      = $Session.Port
            $TokenID   = $Session.TokenID
            $TokenKey  = $Session.Token | Read-SecureString
            if(-Not$TimeOut){$Timeout=($BHSession | ? id -eq $SessID).timeout}
            # Signature
            $Timestamp = [Datetime]::utcnow.tostring('o')
            $KeyByte   = [Text.Encoding]::UTF8.GetBytes($TokenKey)
            $OpByte    = [Text.Encoding]::UTF8.GetBytes("$Method/$URI")
            $DateByte  = [Text.Encoding]::UTF8.GetBytes(-join $Timestamp[0..12])
            $BodyByte  = [Text.Encoding]::UTF8.GetBytes("$Body")
            $HMAC      = [Security.Cryptography.HMACSHA256]::new($KeyByte).ComputeHash($OpByte)
            $HMAC      = [Security.Cryptography.HMACSHA256]::new($HMAC).ComputeHash($DateByte)
            $HMAC      = [Security.Cryptography.HMACSHA256]::new($HMAC).ComputeHash($BodyByte)
            $Sign      = [Convert]::ToBase64String($HMAC)
            # Headers
            $Headers = @{
                Authorization = "BHESignature $TokenID"
                Signature     = $Sign
                RequestDate   = $Timestamp
                }
            if($Timeout -ne $Null){$Headers.add('Prefer',$Timeout)}
            # Verbose
            Write-verbose "[BH] $Method $URI"
            if($Body){Write-Verbose "$Body"}
            # Params
            if($Port){$Server="${server}:${Port}"}
            $Params = @{
                Uri         = "${Proto}://${Server}/${URI}"
                ContentType = if($Method -eq 'POST' -AND $uri -match "saml/providers$"){'multipart/form-data'}else{'application/json'}
                Method      = $Method
                Headers     = $Headers
                UserAgent   = 'PowerShell BloodHound Operator'
                }
            # Body
            if($Body){$Params.Add('Body',"$Body")}
            # Call
            try{$Reply = Invoke-RestMethod @Params -verbose:$false -UseBasicParsing}catch{Get-ErrorWarning;Break}
            # Output
            if($Expand){foreach($Dot in $Expand.split('.')){try{$Reply=$Reply.$Dot}Catch{}}}
            if(($BHSession|? x).count -gt 1 -AND $reply.gettype().name -ne 'string'){$Reply|%{
                $_|Add-Member -MemberType NoteProperty -Name SessionID -Value $SessID -PassThru | select SessionID,* -ea 0
                }}
            else{$Reply}
            }}
    end{}###
    }
#End
#>

<#
.Synopsis
    Invoke BloodHound API call
.DESCRIPTION
    Invoke-RestMethod to Bloodhound API against BHSession
.EXAMPLE
    Invoke-BHAPI /api/version | Select-Object -ExpandProperty data | Select-Object -ExpandProperty server_version
.EXAMPLE
    bhapi api/version -expand data.server_version
.EXAMPLE
    BHAPI bloodhound-users POST $Json
#>
function Invoke-BHAPI{
    [Alias('BHAPI')]
    param(
        # URI
        [Parameter(Mandatory=1)][String]$URI,
        # Method
        [ValidateSet('GET','POST','PATCH','PUT','DELETE')]
        [Parameter(Mandatory=0)][String]$Method='GET',
        # Body
        [Parameter(Mandatory=0)][String]$Body,
        # FIlters
        [Parameter(Mandatory=0)][String[]]$Filter,
        # Session
        [Parameter(Mandatory=0)][int[]]$SessionID=($BHSession | ? x).id,
        # Timeout
        [Parameter(Mandatory=0)][Alias('Prefer')][int]$Timeout,
        # Expand
        [Parameter(Mandatory=0)][Alias('Dot')][String]$Expand,
        # ContentType
        [Parameter(Mandatory=0)][String]$ContentType='application/json'
        )
    begin{
        if(-Not$SessionID){Write-Warning "No BHSession found: Use New-BHSession [Help New-BHSession]";Break}
        if($URI -match "^/"){$URI=$URI.trimstart('/')}
        if($URI -notmatch "^api/"){$URI='api/v2/'+$URI}
        if($filter){$qFilter = '?'+$($Filter.replace(' ','+')-join'&')
            $qfilter=[uri]::EscapeUriString($qFilter)
            $qFilter=$qfilter.trimend('&')
            $URI=$URI+$qfilter
            }
        }
    process{foreach($SessID in $SessionID){
            # Session
            $Session   = $BHSession | ? ID -eq $SessID
            $Proto     = $Session.Protocol
            $Server    = $Session.Server
            $Port      = $Session.Port
            if(-Not$TimeOut){$Timeout=($BHSession | ? id -eq $SessID).timeout}
            ## TokenID/TokenKey
            if($Session.tokenID -ne 'JWT'){
                $TokenID   = $Session.TokenID
                $TokenKey  = $Session.Token | Read-SecureString
                # Signature
                $Timestamp = [Datetime]::utcnow.tostring('o')
                $KeyByte   = [Text.Encoding]::UTF8.GetBytes($TokenKey)
                $OpByte    = [Text.Encoding]::UTF8.GetBytes("$Method/$URI")
                $DateByte  = [Text.Encoding]::UTF8.GetBytes(-join $Timestamp[0..12])
                $BodyByte  = [Text.Encoding]::UTF8.GetBytes("$Body")
                $HMAC      = [Security.Cryptography.HMACSHA256]::new($KeyByte).ComputeHash($OpByte)
                $HMAC      = [Security.Cryptography.HMACSHA256]::new($HMAC).ComputeHash($DateByte)
                $HMAC      = [Security.Cryptography.HMACSHA256]::new($HMAC).ComputeHash($BodyByte)
                $Sign      = [Convert]::ToBase64String($HMAC)
                # Headers
                $Headers = @{
                    Authorization  = "BHESignature $TokenID"
                    Signature      = $Sign
                    RequestDate    = $Timestamp
                    "Content-Type" = $ContentType
                    }}
            ## JWT
            else{$Headers = @{
                Authorization = "Bearer $($Session.Token)"
                "Content-Type" = $ContentType 
                }}
            if($ContentType -eq 'text/csv'){$Headers.add('Accept',"text/csv")}
            if($ContentType -match 'zip'){$Headers.add('X-File-Upload-Name',"unknown.zip")}
            if($Timeout -ne $Null){$Headers.add('Prefer',"wait=$Timeout")}
            # Verbose
            Write-verbose "[BH] $Method $URI"
            if($Body){Write-Verbose "$Body"}
            # Params
            if($Port){$Server="${server}:${Port}"}
            $Params = @{
                Uri         = "${Proto}://${Server}/${URI}"
                #ContentType = $ContentType
                Method      = $Method
                Headers     = $Headers
                UserAgent   = 'PowerShell BloodHound Operator'
                #TimeoutSec  = 300
                }
            # Body
            if($Body -ne $null){$Params.Add('Body',$Body)}
            ## DEBUG
            #RETURN $Params
            # Call
            try{$Reply = Invoke-RestMethod @Params -verbose:$false -UseBasicParsing}catch{Get-ErrorWarning;Break}
            # Output
            if($Expand){foreach($Dot in $Expand.split('.')){try{$Reply=$Reply.$Dot}Catch{}}}
            if(($BHSession|? x).count -gt 1 -AND $reply.gettype().name -ne 'string'){$Reply|%{
                $_|Add-Member -MemberType NoteProperty -Name SessionID -Value $SessID -PassThru | select SessionID,* -ea 0
                }}
            else{$Reply}
            }}
    end{}###
    }
#End




## BloodHound Operator - BHSession
# New-BHSession
# Remove-BHSession
# Select-BHSession
# Get-BHSession
# Set-BHSession

<#
New-BHSession -TokenID $BHTokenID -Token $BHTokenKey
#>
###############################################################>


############################################## New-BHSession

<#
.SYNOPSIS
    New BloodHound API Session
.DESCRIPTION
    New BloodHound API Session
.EXAMPLE
    $TokenKey = Get-Clipboard | Convertto-SecureString -AsPlainText -Force
    
    Convert plaintext token key from clipboard to secure string variable
.EXAMPLE
    New-BHSession -TokenID $TokenID -Token $TokenKey
    
    Create a BHCE session (localhost:8080). 
    - $TokenKey must be secure string.
.EXAMPLE
    New-BHSession -Server $Instance -TokenID $TokenID -Token $TokenKey
    
    Create a BHE session. 
    - $TokenKey must be secure string.
#>
function New-BHSession{
    Param(
        # TokenID
        [Parameter(Mandatory=1)][String]$TokenID=$(Read-Host -Prompt "Enter TokenID"),
        # Token
        [Parameter(Mandatory=1)][Security.SecureString]$Token=$(Read-Host -AsSecureString -Prompt "Enter Token"),
        # Server
        [Parameter(Mandatory=0)][String]$Server='127.0.0.1',
        # Port
        [Parameter(Mandatory=0)][String]$Port,
        # Proto
        [Parameter(Mandatory=0)][String]$Protocol,
        # CypherClip
        [Parameter(Mandatory=0)][Switch]$CypherClip
        )
    # ASCII
    $ASCII= @("
    _____________________________________________
    _______|_____________________________________
    ______||_________________BloodHoundOperator__
    ______||-________...___________________BETA__
    _______||-__--||||||||-._____________________
    ________!||||||||||||||||||--________________
    _________|||||||||||||||||||||-______________
    _________!||||||||||||||||||||||.____________
    ________.||||||!!||||||||||||||||-___________
    _______|||!||||___||||||||||||||||.__________
    ______|||_.||!___.|||'_!||_'||||||!._________
    _____||___!||____|||____||___|||||.__________
    ______||___||_____||_____||!__!|||'__________
    ___________ ||!____||!_______________________
    _____________________________________________
   
    BloodHound Dog Whisperer - @SadProcessor 2024
")  
    # Port & Proto
    if($Server -match "127.0.0.1|localhost" -AND -Not$Port){$Port='8080'}
    if($Server -match "127.0.0.1|localhost" -AND -Not$Protocol){$Protocol='http'}
    if($Server -ne 'localhost' -AND -Not$Protocol){$Protocol='https'}
    # BHFilter
    if(-Not$BHFilter){$Script:BHFilter = Get-BHPathFilter -ListAll | Select Platform,Group,@{n='x';e={'x'} },Edge}
    # BHSession
    if(-Not$BHSession){Write-Host $ASCII -ForegroundColor Blue; $Script:BHSession=[Collections.ArrayList]@()}
    # Unselect all
    $BHSession|? x|%{$_.x=''}
    # Session ID
    $SessionID = ($BHSession.id | sort-object | Select-Object -Last 1)+1 
    # New Session
    $NewSession = [PSCustomObject]@{
        x          = 'x'
        ID         = $SessionID
        Protocol   = $Protocol
        Server     = $Server
        Port       = $Port
        Operator   = 'tbd'
        Role       = 'tbd'
        Edition    = 'tbd'
        Version    = 'tbd'
        Timeout    = 0
        Limit      = 1000
        CypherClip = [Bool]$PSCmdlet.MyInvocation.BoundParameters.CypherClip.IsPresent
        TokenID    = $TokenID
        Token      = $Token
        }
    # Add New Session
    $Null = $BHSession.add($NewSession)
    # Version
    $vers = BHAPI 'api/version' -Expand 'data.server_version' -SessionID $SessionID -verbose:$False
    if(-Not$Vers){
    #($Script:BHSession | ? x).Version = Try{BHAPI 'api/version' -Expand 'data.server_version' -SessionID $SessionID -verbose:$False}Catch{
        $BHSession.Remove($NewSession)
        Write-Warning "Invalid Session Token - No Session Selected"
        RETURN 
        }
    else{($Script:BHSession | ? x).Version = $Vers}
    # Operator
    ($Script:BHSession | ? x).Operator = (BHAPI "api/v2/self" -Expand 'data.principal_name' -SessionID $SessionID -verbose:$False)
    # Role
    ($Script:BHSession | ? x).Role = (BHAPI "api/v2/self" -Expand 'data.roles' -SessionID $SessionID -verbose:$False).name
    # Edition
    $BHEdition = if($NewSession.server -match "\.bloodhoundenterprise\.io$"){'BHE'}else{'BHCE'}
    ($Script:BHSession | ? x).Edition = $BHEdition 
    }
#End



################################################ Remove-BHSession

<#
.SYNOPSIS
    Remove BloodHound API Session
.DESCRIPTION
    Remove BloodHound API Session
.EXAMPLE
    Remove-BHSession
#>
function Remove-BHSession{
    Param(
        [Parameter(Mandatory)][int[]]$ID,
        [Parameter()][Switch]$Force
        )
    Foreach($SessID in $ID){
        if($Force -OR $(Confirm-Action "Remove BHSession ID $SessID")){$BHSession.Remove(($BHSession | ? id -eq $SessID))}}
    }
#End


<#
.SYNOPSIS
    New BloodHound API Session
.DESCRIPTION
    New BloodHound API Session
.EXAMPLE
    $TokenKey = Get-Clipboard | Convertto-SecureString -AsPlainText -Force
    
    Convert plaintext token key from clipboard to secure string variable
.EXAMPLE
    New-BHSession -TokenID $TokenID -Token $TokenKey
    
    Create a BHCE session (localhost:8080). 
    - $TokenKey must be secure string.
.EXAMPLE
    New-BHSession -Server $Instance -TokenID $TokenID -Token $TokenKey
    
    Create a BHE session. 
    - $TokenKey must be secure string.
.EXAMPLE
    New-BHSession -JWT $JWT [-Server $Instance]
    
    Create Session with JWT
#>
function New-BHSession{
    [CmdletBinding(DefaultParameterSetName='JWT')]
    Param(
        # TokenID
        [Parameter(Mandatory=1,ParameterSetName='Token')][String]$TokenID,
        # Token
        [Parameter(Mandatory=1,ParameterSetName='Token')][Security.SecureString]$Token,
        # JWT
        [Parameter(Mandatory=1,Position=0,ParameterSetName='JWT')][String]$JWT,
        # Server
        [Parameter(Mandatory=0)][String]$Server='127.0.0.1',
        # Port
        [Parameter(Mandatory=0)][String]$Port,
        # Proto
        [Parameter(Mandatory=0)][String]$Protocol,
        # CypherClip
        [Parameter(Mandatory=0)][Switch]$CypherClip,
        # Edition
        [VAlidateSet('BHE','BHCE')]
        [Parameter(Mandatory=0)][Alias('Flavor')][Switch]$Edition
        )
    # ASCII
    $ASCII= @("
    _____________________________________________
    _______|_____________________________________
    ______||_________________BloodHoundOperator__
    ______||-________...___________________BETA__
    _______||-__--||||||||-._____________________
    ________!||||||||||||||||||--________________
    _________|||||||||||||||||||||-______________
    _________!||||||||||||||||||||||.____________
    ________.||||||!!||||||||||||||||-___________
    _______|||!||||___||||||||||||||||.__________
    ______|||_.||!___.|||'_!||_'||||||!._________
    _____||___!||____|||____||___|||||.__________
    ______||___||_____||_____||!__!|||'__________
    ___________ ||!____||!_______________________
    _____________________________________________
   
    BloodHound Dog Whisperer - @SadProcessor 2024
")  
    # Server, Port & Proto
    if($Server -match "127.0.0.1|localhost" -AND -Not$Port){$Port='8080'}
    if($Server -match "127.0.0.1|localhost" -AND -Not$Protocol){$Protocol='http'}
    if($Server -ne 'localhost' -AND -Not$Protocol){$Protocol='https'}
    if($Server -match "^https://"){$Server=$Server-replace"^https\:\/\/",'';$Protocol='https'}
    if($Server -match "^http://"){$Server=$Server-replace"^http\:\/\/",'';$Protocol='http'}
    if($Server -notmatch "^http://|^https://" -AND $Server -notmatch "\." -AND $Server -notmatch "127.0.0.1|localhost"){
        $Server+='.bloodhoundenterprise.io'
        }
    # BHFilter
    if(-Not$BHFilter){$Script:BHFilter = Get-BHPathFilter -ListAll | Select Platform,Group,@{n='x';e={'x'} },Edge}
    # BHSession
    if(-Not$BHSession){Write-Host $ASCII -ForegroundColor Blue; $Script:BHSession=[Collections.ArrayList]@()}
    # Unselect all
    $BHSession|? x|%{$_.x=''}
    # Session ID
    $SessionID = ($BHSession.id | sort-object | Select-Object -Last 1)+1 
    # New Session
    $NewSession = [PSCustomObject]@{
        x          = 'x'
        ID         = $SessionID
        Protocol   = $Protocol
        Server     = $Server
        Port       = $Port
        Operator   = 'tbd'
        Role       = 'tbd'
        Edition    = 'tbd'
        Version    = 'tbd'
        Timeout    = 0
        Limit      = 1000
        CypherClip = [Bool]$PSCmdlet.MyInvocation.BoundParameters.CypherClip.IsPresent
        SourceList = @()
        ZoneList   = @()
        TokenID    = if($JWT){'JWT'}else{$TokenID}
        Token      = if($JWT){$JWT}else{$Token}
        }
    # Add New Session
    $Null = $BHSession.add($NewSession)
    # Version
    $vers = BHAPI 'api/version' -Expand 'data' -SessionID $SessionID -verbose:$False
    if(-Not$Vers){
    #($Script:BHSession | ? x).Version = Try{BHAPI 'api/version' -Expand 'data.server_version' -SessionID $SessionID -verbose:$False}Catch{
        #$BHSession.Remove($NewSession)
        Write-Warning "Invalid Session Token - No Session Selected"
        RETURN 
        }
    else{($Script:BHSession | ? x).Version = $Vers.server_version}
    # Operator
    ($Script:BHSession | ? x).Operator = (BHAPI "api/v2/self" -Expand 'data.principal_name' -SessionID $SessionID -verbose:$False)
    # Role
    ($Script:BHSession | ? x).Role = (BHAPI "api/v2/self" -Expand 'data.roles' -SessionID $SessionID -verbose:$False).name
    # Edition <---------- Change
    #$BHEdition = if($Edition){$Edition}else{if($NewSession.server -match "\.bloodhoundenterprise\.io$"){'BHE'}else{'BHCE'}}
    $BHEdition = Switch($Vers.product_edition){Community{'BHCE'}enterprise{'BHE'}}
    ($Script:BHSession | ? x).Edition = $BHEdition 
    # SourceKinds
    $SrcList = Get-BHOpenGraphSourceKind | select id,name #,active
    ($Script:BHSession | ? x).SourceList = $SrcList
    # Zones
    $ZnList = Get-BHAssetGroup | select id,name #,position,kind_id|sort position,name
    ($Script:BHSession | ? x).ZoneList = $ZnList
    # Findings
    if($BHEdition -eq 'BHE'){
        $FList = BHFinding -ListAll
        $Script:BHSession | ? x | Add-Member -MemberType NoteProperty -Name FindingList -Value $FList
        } 
    }
#End


################################################ Select-BHSession

<#
.SYNOPSIS
    Select BloodHound API Session
.DESCRIPTION
    Select BloodHound API Session
.EXAMPLE
    Select-BHSession 1
#>
function Select-BHSession{
    [CmdletBinding(DefaultParameterSetName='ID')]
    [Alias('BHSelect')]
    Param(
        [Parameter(Mandatory,ParameterSetName='ID',Position=0)][Alias('SessionID')][int[]]$ID,
        [Parameter(Mandatory,ParameterSetName='None')][Switch]$None
        )
    if($None){$BHSession |? x|%{$_.x = $Null}}
    Else{
        # Unselect
        $BHSession|? x|%{$_.x = $Null}
        # Select
        $BHSession|? id -in @($ID)|%{$_.x='x'}
        }
    }
#End


################################################ Get-BHSession

<#
.SYNOPSIS
    Get BloodHound API Session
.DESCRIPTION
    Get BloodHound API Session
.EXAMPLE
    Get-BHSession
.EXAMPLE
    Get-BHSession -Selected
#>
function Get-BHSession{
    [Alias('BHSession')]
    Param(
        [Parameter(Mandatory=0)][Alias('Current')][Switch]$Selected
        )
    if($Selected){$BHSession | ? x | Select * -ExcludeProperty Token,TokenID}
    else{$BHSession | Select * -ExcludeProperty Token,TokenID}
    }
#End



################################################ Set-BHSession

<#
.SYNOPSIS
    Set BloodHound API Session
.DESCRIPTION
    Set BloodHound API Session
.EXAMPLE
    Set-BHSession
#>
Function Set-BHSession{
    Param(
        [Parameter()][int]$Limit,
        [ValidateRange(0,3600)][Parameter()][int]$Timeout,
        [Parameter()][Switch]$CypherClip,
        [Parameter()][Switch]$NoClip
        )
    if($Limit){$BHSession|? x |%{$_.Limit=$Limit}}
    if($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("Timeout")){
        #if($Timeout -eq 0){$Timeout=30}
        $BHSession|? x|%{$_.Timeout=$Timeout}
        }
    if($NoClip){($BHSession|? x).CypherClip=$False}
    elseif($CypherClip){($BHSession|? x)|%{$_.CypherClip=$True}}
    }
#End


####################################################### Experimental

<#
.SYNOPSIS
    Invoke BloodHound API Session Script
.DESCRIPTION
    Invoke BloodHound API Session Script
.EXAMPLE
    BHScript {BHOperator -self | select principal_name} -SessionID 1,2
#>
function Invoke-BHSessionScript{
    [Alias('BHScript')]
    Param(
        [Parameter()][ScriptBlock]$Script,
        [Parameter()][int[]]$SessionID=$((BHSession|? x).id)
        )
    Begin{$Selected = (BHSession|? x).id}
    Process{
        Try{Foreach($SessID in $SessionID){
            Select-BHSession -id $SessID
            $res = Invoke-Command $Script -NoNewScope
            If($Selected.count -gt 1){$res|Add-Member -MemberType NoteProperty -Name SessionID -Value $SessID}
            $res
            }}
        catch{}
        Finally{Select-BHSession $Selected}
        }
    End{Select-BHSession $Selected}
    }
#End



## BloodHound Operator - BHServer
# Get-BHServer <--------------------- Removed
# Get-BHServerConfig
# Set-BHServerConfig
# Get-BHServerFeature
# Set-BHServerFeature
# Get-BHServerAuditLog
## ToDo
# Get-BHServerSAMLProvider
# New-BHServerSAMLProvider
# Remove-BHServerSAMLProvider
# Get-BHServerSAMLendpoint



################################################ BHServer

<#
function Get-BHServer{
    [Alias('BHServer')]
    Param(
        [Parameter()]$Status='running'
        )
    $Status=if($Status){"-f status=$Status"}else{$Null}
    try{docker ps --format json $Status| ConvertFrom-Json}catch{}
    }
#End
#>


<#
.SYNOPSIS
    Get BloodHound Server version
.DESCRIPTION
    Get BloodHound Server version
.EXAMPLE
    BHVersion
#>
function Get-BHServerVersion{
    [CmdletBinding()]
    [Alias('BHVersion')]
    Param([Parameter()][Int[]]$SessionID=$((BHSession|? x).id))
    foreach($SessID in $SessionID){
        $Reply = Invoke-BHAPI "api/version" -Expand data -SessionID $SessID | select -exclude API
        $ShHversion = Invoke-BHAPI "api/v2/collectors/sharphound" -Expand data.latest -SessionID $SessID
        $AzHversion = Invoke-BHAPI "api/v2/collectors/azurehound" -Expand data.latest -SessionID $SessID
        #$Extension = Invoke-BHAPI extensions -expand data.extensions -SessionID $SessID | ? is_builtin -eq $false | select name,version
        $Reply | Add-Member -MemberType NoteProperty -Name SharpHound -Value $ShHversion
        $Reply | Add-Member -MemberType NoteProperty -Name AzureHound -Value $AzHversion
        #$Reply | Add-Member -MemberType NoteProperty -Name Extension -Value $Extension
        $Reply
        }}
#####End


function Get-BHServerDogTag{
    [CmdletBinding()]
    [Alias('BHDogTag')]
    Param()
    BHAPI dog-tags -expand data
    }
#End

################################################ Get-BHServerConfig

<#
.SYNOPSIS
    Get BloodHound Server Config
.DESCRIPTION
    Get BloodHound Server Config
.EXAMPLE
    BHConfig
#>
Function Get-BHServerConfig{
    [CmdletBinding()]
    [Alias('BHConfig','Get-BHConfig')]
    Param()
    Invoke-BHAPI 'api/v2/config' -expand data
    }
#End



################################################ Set-BHServerConfig

<#
.SYNOPSIS
    Set BloodHound Server Config
.DESCRIPTION
    Set BloodHound Server Config
.EXAMPLE
    Set-BHConfig -key prune.ttl -value @{base_ttl="P8D";has_session_edge_ttl="P5D"}
.EXAMPLE
    Set-BHConfig -key analysis.reconciliation -value @{enabled=$true}
#>
Function Set-BHServerConfig{
    [Alias('Set-BHConfig')]
    Param(
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)][Alias('key')][string[]]$ConfigKey,
        [Parameter(Mandatory)][HashTable]$Value
        )
    Begin{}
    Process{Foreach($key in $ConfigKey){
        $Body = @{key=$key;value=$Value}|ConvertTo-Json
        Invoke-BHAPI "api/v2/config" -Method PUT -Body $Body
        }}
    End{}
    }
#End



################################################ Get-BHServerFeature

<#
.SYNOPSIS
    Get BloodHound Server Feature
.DESCRIPTION
    Get BloodHound Server Feature
.EXAMPLE
    BHFeature
#>
Function Get-BHServerFeature{
    [CmdletBinding()]
    [Alias('BHFeature')]
    Param()
    Invoke-BHAPI 'api/v2/features' -expand data
    }
#End



################################################ Set-BHServerFeature

<#
.SYNOPSIS
    Set BloodHound Server Feature
.DESCRIPTION
    Set BloodHound Server Feature
.EXAMPLE
    Set-BHFeature -id 1 -Enabled
#>
Function Set-BHServerFeature{
    [Alias('Set-BHFeature')]
    Param(
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)][Alias('ID')][int[]]$FeatureID,
        [Parameter(Mandatory,ParameterSetName='Enable')][Switch]$Enabled,
        [Parameter(Mandatory,ParameterSetName='Disable')][Switch]$Disabled
        )
    Begin{}
    Process{Foreach($ID in $FeatureID){
        $IsEnabled = (Get-BHServerFeature | ? ID -eq $ID).enabled
        if(($PSCmdlet.ParameterSetName -eq 'Enable' -AND -Not$IsEnabled) -OR ($PSCmdlet.ParameterSetName -eq 'Disable' -AND $IsEnabled)){
            Invoke-BHAPI "api/v2/features/$ID/toggle" -Method PUT
            }
        }}
    End{}
    }
#End



################################################ Get-BHServerAuditLog

<#
.SYNOPSIS
    Get BloodHound Server Audit Log
.DESCRIPTION
    Get BloodHound Server Audit Log
.EXAMPLE
    BHAudit
#>
Function Get-BHServerAuditLog{ #<------------------------------------------- /!\ Check Filters /!\
    [Alias('BHAudit')]
    Param(
        [Parameter()][string]$Limit='100',
        [Parameter()][DateTime]$Before,
        [Parameter()][DateTIme]$After,
        [Parameter()][String[]]$Filter,
        [Parameter()][string]$Skip
        )
    [Array]$qFltr=@()
    if($After){$qFltr+="after=$($After|ToBHDate)"}
    if($Before){$qFltr+="before=$($Before|ToBHDate)"}
    if($Skip){$qFltr+="Skip=$Skip"}
    if($Limit){$qFltr+="limit=$Limit"}
    if($Filter.count){$qFltr+=$Filter}
    Invoke-BHAPI 'api/v2/audit' -filter $qFltr -Expand data.logs
    }
#End

<#
Function Get-BHServerAuditLog{ #<------------------------------------------- /!\ Add Filters /!\
    [Alias('BHAudit')]
    Param(
        [Parameter()][Switch]$All
        )
    Invoke-BHAPI 'api/v2/audit' -Expand data.logs
    }
#End
#>


<#
.SYNOPSIS
    Get BloodHound SAML Provider
.DESCRIPTION
    Get BloodHound SAML Provider
.EXAMPLE
    Get-BHServerSAMLProvider
#>
function Get-BHServerSAMLProvider{
    [Alias('BHSAMLProvider')]
    Param(
        [Parameter(Mandatory=0)][Alias('ID')][int]$ProviderID
        )
    if($ProviderID){BHAPI api/v2/saml/providers/$ProviderID -expand data}
    else{BHAPI api/v2/saml -expand data.saml_providers}
    }
#End

<#
.SYNOPSIS
    New BloodHound SAML Provider
.DESCRIPTION
    New BloodHound SAML Provider
.EXAMPLE
    New-BHServerSAMLProvider
#>
function New-BHServerSAMLProvider{
    [Alias('New-BHSAMLProvider')]
    Param(
        [Parameter(Mandatory=1)][String]$Name,
        [Parameter(Mandatory=1)][String]$Metadata
        )
    Write-Warning "/!\ ------------> ToDo <--------------- /!\"
    # multipart/form >> stckvrflw questions 36268925 powershell-invoke-restmethod-multipart-form-data
    #BHAPI api/v2/saml/providers POST -expand data -Body $Metadata
    }
#End


<#
.SYNOPSIS
    Remove BloodHound SAML Provider
.DESCRIPTION
    Remove BloodHound SAML Provider
.EXAMPLE
    Remove-BHServerSAMLProvider -id <id> [-Force]
#>
function Remove-BHServerSAMLProvider{
    [Alias('Remove-BHSAMLProvider')]
    Param(
        [Parameter(Mandatory=1)][Alias('ID')][int]$ProviderID,
        [Parameter(Mandatory=0)][Switch]$Force,
        [Parameter(Mandatory=0)][Switch]$PassThru
        )
    if($Force -OR (Confirm-Action "Remove SAML Provider $ProviderID")){
    $Impacted = BHAPI api/v2/saml/providers/$ProviderID DELETE -Expand data
    if($PassThru){$Impacted}
    }}
#End

<#
.SYNOPSIS
    Get BloodHound SAML Endpoints
.DESCRIPTION
    Get BloodHound SAML Endpoints
.EXAMPLE
    Get-BHServerSAMLEndpoint
#>
function Get-BHServerSAMLEndpoint{
    [Alias('BHSAMLEndpoint')]
    Param()
    BHAPI api/v2/saml/sso -Expand data.endpoints
    }
#End

## BloodHound Operator - BHOperator
# Get-BHOperator
# New-BHOperator
# Set-BHOperator
# Remove-BHOperator
# Set-BHOperatorSecret
# Revoke-BHOperatorSecret
# Get-BHOperatorMFAStatus
# Get-BHOperatorRole
# Get-BHOperatorPermission
# Get-BHOperatorToken
# New-BHOperatorToken
# Revoke-BHOperatorToken
# Get-BHOperatorHelp
# Get-BHOperatorAccessControl
# Set-BHOperatorAccessControl

################################################ Get-BHOperator

<#
.Synopsis
    Get BloodHound Operator
.DESCRIPTION
    Get BloodHound Operator
.EXAMPLE
    BHOperator
#>
Function Get-BHOperator{
    [CmdletBinding(DefaultParameterSetName='All')]
    [Alias('BHOperator')]
    Param(
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,ParameterSetName='ByID')][string[]]$ID,
        [Parameter(Mandatory,ParameterSetName='ByName')][String[]]$Name,
        [Parameter(Mandatory,ParameterSetName='Self')][Alias('Self','Whoami')][Switch]$Current,
        [ValidateScript({$_ -in (Get-BHOperatorRole).name})]
        [Parameter(Mandatory,ParameterSetName='ByRole')][String]$Role
        )
    Begin{$Collect=[Collections.ArrayList]@()}
    Process{Foreach($OperatorID in $ID){$Null=$Collect.Add($OperatorID)}}
    End{$Reply = Switch($PSCmdlet.ParameterSetName){
            ByID    {Foreach($OperatorID in $Collect){Invoke-BHAPI api/v2/bloodhound-users/$OperatorID -expand data}}
            Self    {Invoke-BHAPI api/v2/self -expand data}
            Default {Invoke-BHAPI api/v2/bloodhound-users -expand data.users}
            }
        $Reply = Switch($PSCmdlet.ParameterSetName){
            ByName  {$Reply | ? {$_.'Principal_Name' -in $Name}}
            ByRole  {$Reply | ? {$_.Roles.Name -eq $Role}}
            Default {$Reply}
            }
        $Reply
        }
    }
#End


################################################ New-BHOperator

<#
.Synopsis
    New BloodHound Operator
.DESCRIPTION
    New BloodHound Operator
.EXAMPLE
    New-BHOperator -name bob
#>
Function New-BHOperator{
    Param(
        [Parameter(Mandatory=1)][Alias('Principal_Name')][String]$Name,
        [Parameter(Mandatory=0)][String]$FirstName,
        [Parameter(Mandatory=0)][String]$LastName,
        [Parameter(Mandatory=0)][String]$Email,
        [Parameter(Mandatory=0)][Int[]]$Role,
        #[Parameter(Mandatory=0)][String]$Secret,
        [Parameter(Mandatory=0)][Switch]$PassThru
        )
    NoMultiSession
    # Body
    $Body = @{
        principal      = $Name
        first_name     = $FirstName
        last_name      = $LastName
        email_address  = $Email
        roles          = $Role
        secret         = $null
        } | ConvertTo-Json
    # Call
    $Operator = Invoke-BHAPI 'api/v2/bloodhound-users' -Method POST -Body $Body
    # Secret
    #if($Secret){$Operator|Set-BHOperatorSecret -Secret $Secret}
    # Ouptut
    if($PassThru){$Operator}
    }
#End


################################################ Set-BHOperator

<#
.Synopsis
    Set BloodHound Operator
.DESCRIPTION
    Set BloodHound Operator
.EXAMPLE
    BHOperator -id 2 | Set-BHOperator -firstname alice
#>
Function Set-BHOperator{
    Param(
        [Parameter(Mandatory=1,ValueFromPipeline,ValueFromPipelineByPropertyName)][Alias('ID')][String]$OperatorID,
        [Parameter(Mandatory=0)][Alias('Principal_Name')][String]$Name,
        [Parameter(Mandatory=0)][String]$FirstName,
        [Parameter(Mandatory=0)][String]$LastName,
        [Parameter(Mandatory=0)][String]$Email,
        [Parameter(Mandatory=0)][Int[]]$Role,
        [Parameter(Mandatory=0)][Switch]$PassThru
        )
    Begin{NoMultiSession}
    Process{Foreach($ID in $OperatorID){
        $Operator = Get-BHOperator -ID $OperatorID -Verbose:$False
        # Body
        $Body=@{
            principal     = if($Name){$Name}else{$Operator.principal_name}
            first_name    = if($FirstName){$FirstName}else{$Operator.first_name}
            last_name     = if($LastName){$LastName}else{$Operator.last_name}
            Email         = if($Email){$Email}else{$Operator.email_address}
            #roles         = if($Role.count){[Array]@($Role)}else{[Array]@($($Operator.roles.id))}
            roles         = @($Role)
            is_disabled   = $Operator.is_disabled
            }
        $Body = $Body | ConvertTo-Json
        # Call
        Invoke-BHAPI "api/v2/bloodhound-users/$ID" -Method PATCH -Body $Body
        if($PassThru){Get-BHOperator -ID $ID -Verbose:$False}
        }}
    End{}
    }
#End


<#
.Synopsis
    Enable BloodHound Operator
.DESCRIPTION
    Enable BloodHound Operator
.EXAMPLE
    BHOperator -id 2 | Enable-BHOperator
#>
function Enable-BHOperator{
    Param(
        [Parameter(Mandatory=1,ValueFromPipeline,ValueFromPipelineByPropertyName)][Alias('ID')][String[]]$OperatorID,
        [Parameter(Mandatory=0)][Switch]$PassThru
        )
    Begin{NoMultiSession}
    Process{Foreach($OperID in $OperatorID){
        $Operator = Get-BHOperator -ID $OperID -Verbose:$False
        # Body
        $Body=@{
            principal     = $Operator.principal_name
            first_name    = $Operator.first_name
            last_name     = $Operator.last_name
            email_address = $Operator.email_address
            roles         = [Array]@(,$($Operator.roles.id))
            is_disabled   = $False
            }
        $Body = $Body | ConvertTo-Json
        # Call
        Invoke-BHAPI "api/v2/bloodhound-users/$OperID" -Method PATCH -Body $Body
        if($PassThru){Get-BHOperator -ID $OperID -Verbose:$False}
        }}
    End{}
    }
#end


<#
.Synopsis
    Disable BloodHound Operator
.DESCRIPTION
    Disable BloodHound Operator
.EXAMPLE
    BHOperator -id 2 | Disable-BHOperator
#>
function Disable-BHOperator{
    Param(
        [Parameter(Mandatory=1,ValueFromPipeline,ValueFromPipelineByPropertyName)][Alias('ID')][String[]]$OperatorID,
        [Parameter(Mandatory=0)][Switch]$PassThru
        )
    Begin{NoMultiSession}
    Process{Foreach($OperID in $OperatorID){
        $Operator = Get-BHOperator -ID $OperID -Verbose:$False
        # Body
        $Body=@{
            principal     = $Operator.principal_name
            first_name    = $Operator.first_name
            last_name     = $Operator.last_name
            email_address = $Operator.email_address
            roles         = [Array]@(,$($Operator.roles.id))
            is_disabled   = $True
            }
        $Body = $Body | ConvertTo-Json
        # Call
        Invoke-BHAPI "api/v2/bloodhound-users/$OperID" -Method PATCH -Body $Body
        if($PassThru){Get-BHOperator -ID $OperID -Verbose:$False}
        }}
    End{}
    }
#End


################################################ Remove-BHOperator

<#
.Synopsis
    Remove BloodHound Operator
.DESCRIPTION
    Remove BloodHound Operator
.EXAMPLE
    Remove-BHOperator
#>
Function Remove-BHOperator{
    Param(
        [Parameter(Mandatory=1,ValueFromPipeline,ValueFromPipelineByPropertyName)][Alias('ID')][String[]]$OperatorID,
        [Parameter(Mandatory=0)][Switch]$Force
        )
    Begin{NoMultiSession}
    Process{Foreach($ID in $OperatorID){
        $Operator = (Get-BHOperator -ID $ID -Verbose:$False).principal_name
        if($Force -OR (Confirm-Action "Delete Operator $Operator")){Invoke-BHAPI "api/v2/bloodhound-users/$ID" -Method DELETE}
        }}
    End{}
    }
#End


<#
.Synopsis
    Get BloodHound Operator MFA status
.DESCRIPTION
    Get BloodHound MFA status
.EXAMPLE
    BHOperator -self | Get-BHOperatorMFAStatus
#>
function Get-BHOperatorMFAStatus{
    [Alias('BHOperatorMFA')]
    Param(
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)][String[]]$ID
        )
    Begin{NoMultiSession}
    Process{Foreach($OperID in $ID){
        [PSCustomObject]@{
            ID     = $OperID
            Name   = Invoke-BHAPI api/v2/bloodhound-users/$OperId -expand data.principal_name 
            MFA    = Invoke-BHAPI api/v2/bloodhound-users/$OperId/mfa-activation -expand data.status
            }}}
    End{}###
    }
#End

## /!\ ToDo: more MFA cmdlets 

################################################ Set-BHOperatorSecret

<#
.Synopsis
    Set BloodHound Operator Secret
.DESCRIPTION
    Set BloodHound Operator Secret
.EXAMPLE
    Set-BHSecret
#>
Function Set-BHOperatorSecret{
    [Alias('Set-BHSecret')]
    Param(
        [Parameter(Mandatory=1,ValueFromPipeline,ValueFromPipelineByPropertyName)][Alias('ID')][String]$OperatorID,
        [Parameter(Mandatory=0)][Alias('Password')][String]$Secret='BloodHoundPassword123!',
        [Parameter(Mandatory=0)][Switch]$RequireReset,
        [Parameter(Mandatory=0)][Switch]$Force
        )
    Begin{NoMultiSession}
    Process{Foreach($ID in $OperatorID){
        $Operator = Get-BHOperator -ID $ID -Verbose:$False
        if($Force -OR (Confirm-Action "Set password for operator $($Operator.principal_name)")){
            # Body
            $Body=@{
                needs_password_reset = if($Secret -eq 'BloodHoundPassword123!'){$true}else{$PSCmdlet.MyInvocation.BoundParameters['RequireReset'].IsPresent}
                secret               = $Secret
                }
            $Body = $Body | ConvertTo-Json
            # Call
            Invoke-BHAPI "api/v2/bloodhound-users/$ID/secret" -Method PUT -Body $Body
            if($PassThru){Get-BHOperator -ID $ID -Verbose:$False}
            }}}
    End{}###
    }
#End



################################################ Revoke-BHOperatorSecret

<#
.Synopsis
    Revoke BloodHound Operator Secret
.DESCRIPTION
    Revoke BloodHound Operator Secret
.EXAMPLE
    Revoke-BHSecret
#>
Function Revoke-BHOperatorSecret{
    [Alias('Revoke-BHSecret')]
    Param(
        [Parameter(Mandatory=1,ValueFromPipeline,ValueFromPipelineByPropertyName)][Alias('ID')][String]$OperatorID,
        [Parameter(Mandatory=0)][Switch]$Force
        )
    Begin{NoMultiSession}
    Process{Foreach($ID in $OperatorID){
        $Operator = Get-BHOperator -ID $ID -Verbose:$False
        if($Force -OR (Confirm-Action "Expire secret for operator $($Operator.principal_name)")){
            # Call
            Invoke-BHAPI "api/v2/bloodhound-users/$ID/secret" -Method DELETE
            }}}
    End{}###
    }
#End



################################################ Get-BHOperatorRole

<#
.Synopsis
    Get BloodHound Operator Role
.DESCRIPTION
    Get BloodHound Operator Role
.EXAMPLE
    BHRole
#>
Function Get-BHOperatorRole{
    [Alias('BHRole')]
    Param(
        [Parameter()][Alias('self','Whoami')][Switch]$Current
        )
    # Current
    if($Current){(Invoke-BHAPI api/v2/self -expand data).roles.name}
    # All
    else{Invoke-BHAPI api/v2/roles -expand data.roles}
    }
#End



################################################ Get-BHOperatorPermission

<#
.Synopsis
    Get BloodHound Operator Permission
.DESCRIPTION
    Get BloodHound Operator Permission
.EXAMPLE
    BHPermission
#>
Function Get-BHOperatorPermission{
    [Alias('BHPermission')]
    Param(
        [Parameter()][Alias('self')][Switch]$Current
        )
    # Current
    if($Current){(Invoke-BHAPI api/v2/self -expand data).Roles.Permissions.name}
    # All
    else{Invoke-BHAPI api/v2/permissions -expand data.permissions}
    }
#End



################################################ Get-BHOperatorToken

<#
.Synopsis
    Get BloodHound Operator Token
.DESCRIPTION
    Get BloodHound Operator Token
.EXAMPLE
    BHToken
#>
Function Get-BHOperatorToken{
    [Alias('BHToken')]
    Param(
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)][Alias('principal_name')][String[]]$Operator
        )
    Begin{
        $Tokens = Invoke-BHAPI api/v2/tokens -expand data.tokens
        $Operators = [Collections.ArrayList]@()
        }
    Process{Foreach($Name in $Operator){
            $Null=$Operators.add($Name)
            }}
    End{if($Name){
            $OperatorIDs = (Get-BHOperator -Name $Operators).id
            $Tokens|? {$_.'user_id' -in $($OperatorIDs)}
            }
        else{$Tokens}
        }}
#####End



################################################ New-BHOperatorToken

<#
.Synopsis
    New BloodHound Operator Token
.DESCRIPTION
    New BloodHound Operator Token
.EXAMPLE
    New-BHToken -ID $OperatorID -TokenName $TokenName
#>
Function New-BHOperatorToken{
    [Alias('New-BHToken')]
    Param(
        # OperatorID
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineBYPropertyName)][Alias('ID')][String]$OperatorID,
        # TokenName
        [Parameter(Mandatory=0)][String]$TokenName,
        # AsPlainText
        [Parameter()][Switch]$AsPlainText,
        # Confirm
        [Parameter()][Switch]$Force
        )
    Begin{NoMultiSession}
    Process{Foreach($ID in $OperatorID){
        # token name
        if(-Not$TokenName){$TokenName = "Token_$ID"}
        $Operator = Get-BHOperator -ID $ID -Verbose:$False
        if($Force -OR (Confirm-Action "Generate token for operator $($Operator.principal_name)")){
            # Body
            $Params = @{
                token_name = $TokenName
                user_id    = $ID
                } | ConvertTo-Json
            # Call
            $ApiToken = Invoke-BHAPI 'api/v2/tokens' -Method POST -Body $Params -Expand data
            # Secure String
            if(-Not$AsPlainText){$ApiToken.key=$Apitoken.Key|ConvertTo-SecureString -AsPlainText -Force}
            # Output
            $ApiToken
            }}}
    End{}###
    }
#End



################################################ Revoke-BHOperatorToken

<#
.Synopsis
    Revoke BloodHound Operator Token
.DESCRIPTION
    Revoke BloodHound Operator Token
.EXAMPLE
    Revoke-BHToken
#>
Function Revoke-BHOperatorToken{
    [Alias('Revoke-BHToken')]
    Param(
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)][Alias('id')][String[]]$TokenID,
        [Parameter()][Switch]$Force
        )
    Begin{NoMultiSession}
    Process{foreach($Token in $TokenID){
        if($Force -OR (Confirm-Action "Revoke Token $Token")){Invoke-BHAPI -Method DELETE "api/v2/tokens/$token"}
        }}
    End{}
    }
#End


####################################################### ETAC

function Get-BHOperatorAccessControl{
    [CmdletBinding(DefaultParameterSetName='All')]
    [Alias('BHAccessControl','Get-BHAccessControl','BHEtac')]
    Param(
        [Parameter(Mandatory=1,ParameterSetName='OID',ValueFromPipelineByPropertyName=1)][Alias('id')][String[]]$OperatorID,
        [Parameter(Mandatory=1,ParameterSetName='EID')][String]$EnvironmentID
        )
    Begin{
        $AC = BHOperator | select Principal_name,@{n='Role';e={$_.roles.name}},all_environments,@{n='Access';e={$_.environment_targeted_access_control.environment_id}},id
        }
    Process{Foreach($ID in $OperatorID){$AC | ? id -eq $ID}}
    End{Switch($PSCmdlet.ParameterSetName){
        EID{$AC|?{$_.all_environments -OR $_.Access -match $EnvironmentID}}
        All{$AC}
        }}
    }
#End

Function Set-BHOperatorAccessControl{
    [CmdletBinding(DefaultParameterSetName='Add')]
    [Alias('Set-BHAccessControl','Set-BHEtac')]
    Param(
        [Parameter(Mandatory=1,Position=0,ParameterSetName='Add')][String[]]$Add,
        [Parameter(Mandatory=1,ParameterSetName='Remove')][String[]]$Remove,
        [Parameter(Mandatory=1,ValueFromPipelineByPropertyName=1)][String[]]$ID,
        [Parameter(Mandatory=0)][Switch]$Force
        )
    Begin{$AC = BHAccessControl}
    Process{foreach($Operator in $ID){
        $OpAC = $AC | ? id -eq $Operator
        if($OpAc.access -eq $null){$OpAc.Access = @()}
        Switch($PSCmdlet.ParameterSetName){
            Add{Foreach($Env in $Add){$OpAC.Access += $Env}}
            Remove{
                if($Remove -eq '*'){$Remove = $OpAC.Access}
                Foreach($Env in $Remove){$OpAC.Access = $OpAC.access | ?{$_ -ne $Env}}
                }
            }
        $Envs = @($OpAc.access | Sort -Unique | %{[PSCustomObject]@{environment_id=$_}})
        $AllEnvs = $false
        if($Add -eq '*'){$AllEnvs=$True;$envs=@()}
        $Body = @{
            all_environments = $AllEnvs
            environment_targeted_access_control = @{environments = $Envs}
            } | Convertto-json -depth 21
        if($Force -OR $(Confirm-Action "$($PSCmdlet.ParameterSetName) access for $($Opac.principal_name)")){
            #Body
            BHAPI bloodhound-users/$Operator PATCH $Body
            }
        }}
    End{}
    }
#End

## BloodHound Operator - BHData
# Get-BHDataUpload
# New-BHDataUpload
# Invoke-BHDataUpload
# Read-BHDataSource
# Get-BHData
# Get-BHDataCollector
# Import-BHDataCollector
# Start-BHDataAnalysis



################################################ Get-BHDataUpload

<#
.Synopsis
    Get BloodHound Data Upload
.DESCRIPTION
    Get BloodHound Data upload
.EXAMPLE
    Get-BHDataUpload
.EXAMPLE
    Get-BHDataUpload -limit 10
#>
Function Get-BHDataUpload{
    [Alias('BHUpload')]
    Param(
        [Parameter(Mandatory=0)][String]$ID,
        [Parameter(Mandatory=0)][String]$Expand='data',
        [Parameter(Mandatory=0)][int]$Limit=1
        )
    $URI = if($ID){"api/v2/file-upload/$ID/completed-tasks"}else{'api/v2/file-upload'}
    if($Limit -AND -not$ID){$URI += "?limit=$Limit"}
    Invoke-BHAPI $URI -expand $Expand
    }
#End



################################################ New-BHDataUpload

<#
.Synopsis
    New BloodHound Data Upload
.DESCRIPTION
    New BloodHound Data upload
.EXAMPLE
    BHDataUploadJSON $JSON
#>
function New-BHDataUpload{
    [Alias('BHDataUploadJSON')]
    param(
        [Parameter(Mandatory=1,ValueFromPipeline)][Alias('JSON')][String[]]$UploadJSON
        )
    Begin{ # Begin upload > ID
        $Upl = Invoke-BHAPI "api/v2/file-upload/start" -Method POST -expand data
        }
    Process{# Add files to Upload ID
        Foreach($JSON in $UploadJSON){
            $Null = Invoke-BHAPI "api/v2/file-upload/$($Upl.ID)" -Method POST -body $JSON
            }}
    End{# submit Upload ID
        $Null = Invoke-BHAPI "api/v2/file-upload/$($Upl.ID)/end" -Method POST
        }}
#####End



################################################ Invoke-BHDataUpload

<#
.Synopsis
    Invoke BloodHound Data Upload
.DESCRIPTION
    Invoke BloodHound Data upload
.EXAMPLE
    BHDataUpload $Zip
#>
function Invoke-BHDataUpload{
    [Alias('BHDataUpload')]
    param(
        [Parameter(Mandatory=1,ValueFromPipeline,ValueFromPipelineByPropertyName)][Alias('Json')][String[]]$Data,
        [Parameter(Mandatory=0)][int]$Split
        )
    Begin{# Start upload sequence (>> ID)
        $Upl = Invoke-BHAPI "api/v2/file-upload/start" -Method POST -expand data -verbose:$false
        Write-Verbose "Creating Upload ID $($Upl.id)"
        }
    Process{# Add files
        Foreach($Json in ($Data | Read-BHDataSource -Split $Split)){
            Write-Verbose "Adding $($Json.Count) $($Json.type.trimend('s'))$(if($Json.Count -gt 1){'s'}) from $($Json.Source) to Upload ID $($Upl.id)"
            $Null = Invoke-BHAPI "api/v2/file-upload/$($Upl.ID)" -Method POST -body $JSON.data -verbose:$false -wa Stop
            }
        }
    End{# End upload sequence
        Write-Verbose "Starting Upload ID $($Upl.id)"
        $Null = Invoke-BHAPI "api/v2/file-upload/$($Upl.ID)/end" -Method POST -verbose:$false
        }
    }
#End



################################################ Read-BHDataSource

<#
.Synopsis
    Read BloodHound Data Source
.DESCRIPTION
    Read BloodHound Data Source
.EXAMPLE
    Read-BHDataSource $Zip -Split 5000
#>
function Read-BHDataSource{
    [Alias('BHRead')]
    Param(
        [Parameter(Mandatory=1,ValueFromPipeline=1)][String[]]$Source,
        [Parameter()][Int]$Split,
        [Parameter()][Switch]$Unpack
        )
    Begin{}
    Process{foreach($Obj in $Source){
            $Src='Raw Json Input'
            $Json=if(Test-Path $Obj){$Src = Split-Path $Obj -leaf
                if($Obj -match "\.json$"){Get-Content $Obj -Raw}
                if($Obj -match "\.zip$"){Read-ZipContent $Obj}
                }
            else{$Obj}
            foreach($JsonData in ($JSON)){
                $JsonData = $JsonData | ConvertFrom-Json | ConvertTo-Json -depth 21 -Compress
                # AD
                if($JsonData -match ',"meta":{"methods":'){
                    $meta = '{"methods":' + ($JsonData -split ',"meta":{"methods":')[1].trimend('}') + '}' | Convertfrom-JSON
                    $meta | Add-Member -MemberType NoteProperty -Name 'Source' -Value $Src
                    $data = ($JsonData -split ',"meta":{"methods":')[0].replace('{"data":[','[')
                    $meta | Add-Member -MemberType NoteProperty -Name 'Data' -Value $JsonData
                    # Split
                    if($Split -AND $($Meta | Select-object -expand Count) -gt $Split){
                        foreach($SplitData in (($Meta.Data | Convertfrom-Json).data | Split-Collection $Split)){
                            [PSCustomObject]@{
                                methods = $Meta.methods
                                type    = $Meta.Type
                                count   = $SplitData.count
                                Version = $Meta.Version
                                Source  = $Meta.Source
                                Data    = '{"data":' + $($SplitData | Convertto-JSON -depth 11 -Compress)+',"meta":'+$([PSCustomObject]@{methods=$Meta.Methods;type=$Meta.type;count=$SplitData.count;version=$Meta.version } | Convertto-json -compress)+'}'
                                }
                            }
                        }
                    Else{$Meta}
                    }
                # AZ
                if($JsonData -match '"meta":{"type":"azure"'){
                    $Meta = ($Jsondata -split '"meta":{"type":"azure"')[1].trim().trimend('}')
                    $Meta = ('{"type":"azure"' + $meta + '}') | Convertfrom-json
                    $meta | Add-Member -MemberType NoteProperty -Name 'Source' -Value $Src
                    $meta | Add-Member -MemberType NoteProperty -Name 'Data' -Value $Jsondata
                    # Split
                    if($Split -AND $($Meta | Select-object -expand Count) -gt $Split){
                        foreach($SplitData in (($Meta.Data | Convertfrom-Json).data | Split-Collection $Split)){
                            [PSCustomObject]@{
                                type    = $Meta.Type
                                count   = $SplitData.count
                                Version = $Meta.Version
                                Source  = $Meta.Source
                                Data    = '{"data":' + $($SplitData | Convertto-JSON -depth 11 -Compress)+',"meta":'+$([PSCustomObject]@{type=$Meta.type;count=$SplitData.count;version=$Meta.version}|Convertto-json -compress)+'}'
                                }
                            }
                        }
                    Else{$Meta}
                    }
                }
            }
        }
    End{}
    }
#End


################################################ Get-BHData

<#
.Synopsis
    Get BloodHound Data
.DESCRIPTION
    Get BloodHound Data Stats
.EXAMPLE
    BHData -ListDomain
.EXAMPLE
    BHData -Platform AD
.EXAMPLE
    BHData -id $DomainID
.EXAMPLE
    BHData
#>
function Get-BHData{
    [CmdletBinding(DefaultParameterSetName='Stats')]
    [Alias('BHData')]
    Param(
        [Parameter(Position=0,ValueFromPipeline,ValueFromPipelineByPropertyName,ParameterSetName='Stats')][Alias('objectid')][String[]]$ID,
        [Parameter(Mandatory=1,ParameterSetName='ListDomain')][Switch]$ListDomain,
        [Parameter(Mandatory=0,ParameterSetName='ListDomain')][Switch]$Collected,
        [ValidateSet('AD','AZ')]
        [Parameter(Mandatory=1,ParameterSetName='Platform')][String]$Platform,
        [Parameter(Mandatory=1,ParameterSetName='Pipe')][Switch]$PipeStatus,
        [Parameter(Mandatory=0)][int]$Limit=1,
        [Parameter(Mandatory=0)][String[]]$Filter,
        [Parameter(Mandatory=0)][String]$Expand='data'
        )
    Begin{# Prep Filter
        [Array]$qfilter=@()
        if($Limit){$qFilter+="limit=$limit"}
        if($Collected){$qFilter+="collected=eq:True"}
        if($Filter){$qFilter+=$filter}
        # Call
        if($PSCmdlet.ParameterSetName -eq 'Platform'){Switch($Platform){
            AD{Invoke-BHAPI "api/v2/platform/ad/data-quality-stats" -Filter $qFilter -expand $Expand}
            AZ{Invoke-BHAPI "api/v2/platform/azure/data-quality-stats" -Filter $qFilter -expand $Expand}
            }}
        if($PSCmdlet.ParameterSetName -eq 'Pipe'){Invoke-BHAPI api/v2/datapipe/status -Filter $qFilter -expand data}
        }
    Process{
        if($PSCmdlet.ParameterSetName -eq 'Stats'){
            if($ID){Foreach($ObjID in $ID){
                    if($ObjID -match '^S-1-5-21'){Invoke-BHAPI "api/v2/ad-domains/$ObjID/data-quality-stats" -Filter $qFilter  -expand $Expand} 
                    else{Invoke-BHAPI "api/v2/azure-tenants/$ObjID/data-quality-stats" -Filter $qFilter -expand $Expand}
                    }}
            else{Invoke-BHAPI 'api/v2/completeness' -Filter $qFilter -expand $Expand}
            }}
    End{if($PSCmdlet.ParameterSetName -eq 'ListDomain'){Invoke-BHAPI api/v2/available-domains -Filter $qFilter -expand $Expand}}
    }
#End




################################################ Get-BHDataCollector

<#
.Synopsis
    Get BloodHound Data Collector
.DESCRIPTION
    Get BloodHound Data Collector Info
.EXAMPLE
    Get-BHDataCollector
#>
function Get-BHDataCollector{
    [Alias('BHCollector')]
    Param(
        [ValidateSet('SharpHound','AzureHound')][Parameter()][String[]]$Collector=('SharpHound','AzureHound')
        )
    foreach($Hound in $Collector){foreach($SessID in ($BHSession|? x).id){
        $Coll  = Invoke-BHAPI api/v2/collectors/$($Hound.tolower()) -Sessionid $SessID -expand data
        $Check = Invoke-BHAPI api/v2/collectors/$($Hound.tolower())/$($Coll.latest)/checksum -Sessionid $SessID
        [PSCustomObject]@{
            Collector = $Hound.tolower()
            Latest    = $Coll.latest
            File      = $Check.trim().split(' ')[-1].trim()
            Checksum  = $Check.trim().split(' ')[0].trim()
            Versions  = $Coll.versions
            }
        }}
    }
#End


############################################

<#
.SYNOPSIS
    Start BloodHound Data Analysis
.DESCRIPTION
    Start BloodHound Data Analysis
.EXAMPLE
    Start-BHDataAnalysis
#>
function Start-BHDataAnalysis{
    [CmdletBinding()]
    [Alias('BHDataAnalysis')]
    Param()
    BHAPI api/v2/analysis PUT
    }
#End



#################### 



<#
.SYNOPSIS
    Clear BloodHound Database
.DESCRIPTION
    Clear BloodHound Database
.EXAMPLE
    Clear-BHDatabase -GraphData -Force -Really
#>
function Clear-BHDatabase{
    Param(
        [Parameter()][Switch]$GraphData,
        #[Parameter()][Switch]$CustomSelector,
        [Parameter()][Switch]$IngestHistory,
        [Parameter()][Switch]$DataHistory,
        [Parameter()][Switch]$Force,
        [Parameter()][Switch]$Really
        )
    NoMultiSession
    $ClearItem = @{}
    if($GraphData){$ClearItem['deleteCollectedGraphData']=$true}
    #if($CustomSelector){$ClearItem['deleteCustomHighValueSelectors']=$true}
    if($IngestHistory){$ClearItem['deleteFileIngestHistory']=$true}
    if($DataHistory){$ClearItem['deleteDataQualityHistory']=$true}
    if($ClearItem -AND $($Force -OR $(Confirm-Action "Can't undo later... Are you sure"))){
        if($Really -OR $(Confirm-Action "This is irreversible... Are you really sure")){
            ## Comment line below to remove BHE safety - Don't blame me if you wipe your instance ##
            if($(BHSession|? x).edition -eq 'BHE'){RETURN 'Computer Says No... ¯\_(ツ)_/¯'}
            # Clear DB
            BHAPI api/v2/clear-database POST $($ClearItem|Convertto-Json)
            }
        }
    }
#End


function Clear-BHDatabase{
    Param(
        [ValidateSet('AD','AZ','OG')]
        [Parameter()][String[]]$GraphData,
        [ValidateSet('HighValue','AssetGroup')]
        [Parameter()][String[]]$CustomSelector,
        [Parameter()][Switch]$IngestHistory,
        [Parameter()][Switch]$DataHistory,
        [Parameter()][Switch]$Force,
        [Parameter()][Switch]$Really
        )
    NoMultiSession
    $ClearItem = @{}
    if($GraphData){
        $GD = [Array]@()
        If('AD' -in $GraphData){$GD+=1}
        If('AZ' -in $GraphData){$GD+=2}
        If('OG' -in $GraphData){$GD+=0}
        $ClearItem['deleteSourceKinds']=$GD
        $ClearItem['deleteCollectedGraphData']=$False
        }
    if($CustomSelector){
        $CS = [Array]@()
        if('HighValue' -in $CustomSelector){$CS+=1}
        if('AssetGroup' -in $CustomSelector){$CS+=2}
        $ClearItem['deleteAssetGroupSelectors']=$CS
        }
    if($IngestHistory){$ClearItem['deleteFileIngestHistory']=$true}
    if($DataHistory){$ClearItem['deleteDataQualityHistory']=$true}
    if($ClearItem -AND $($Force -OR $(Confirm-Action "Can't undo later... Are you sure"))){
        if($Really -OR $(Confirm-Action "This is irreversible... Are you really sure")){
            ## Comment line below to remove BHE safety - Don't blame me if you wipe your instance ##
            #if($(BHSession|? x).edition -eq 'BHE'){RETURN 'Computer Says No... ¯\_(ツ)_/¯'}
            #DEBUG
            $($ClearItem|Convertto-Json)
            # Clear DB
            #BHAPI api/v2/clear-database POST $($ClearItem|Convertto-Json)
            }
        }
    }
#End



function Clear-BHDatabase{
    Param(
        #[ValidateSet('AD','AZ','OG')]
        #[Parameter()][String[]]$GraphData,
        [ValidateSet('HighValue','AssetGroup')]
        [Parameter()][String[]]$CustomSelector,
        [Parameter()][Switch]$IngestHistory,
        [Parameter()][Switch]$DataHistory,
        [Parameter()][Switch]$Force,
        [Parameter()][Switch]$IKnowWhatImDoing
        )
    DynamicParam{
        $Dico = New-Object Management.Automation.RuntimeDefinedParameterDictionary
        # Prep DynNamelist
        $DynSrcList = (BHSession | ? x).sourcelist.name
        $DynSrcList += 'AllData'
        # Prep DynP
        $DynGD = DynP -Name 'GraphData' -Type 'String[]' -Mandat 0 -VSet $DynSrcList
        # DynP to Dico
        $Dico.Add("GraphData",$DynGD)
        # Return Dico
        Return $Dico
        }
    Begin{NoMultiSession
        # Prep
        $SrcList = (BHSession | ? x).sourcelist.name
        }
    Process{
    $GraphData = ($DynGD|? name -eq GraphData).value
    $ClearItem = @{}
    if($GraphData){
        $GD = Foreach($Knd in $GraphData){($SrcList | ? name -eq $Knd).id}
        $ClearItem['deleteSourceKinds']=@($GD)
        $ClearItem['deleteCollectedGraphData']=$False
        }
    if($CustomSelector){
        $CS = [Array]@()
        if('HighValue' -in $CustomSelector){$CS+=1}
        if('AssetGroup' -in $CustomSelector){$CS+=2}
        $ClearItem['deleteAssetGroupSelectors']=$CS
        }
    if($IngestHistory){$ClearItem['deleteFileIngestHistory']=$true}
    if($DataHistory){$ClearItem['deleteDataQualityHistory']=$true}
    if($ClearItem -AND $($Force -OR $(Confirm-Action "Can't undo later... Are you sure"))){
        if($IknowWhatImDoing -OR $(Confirm-Action "This is irreversible... Are you really sure")){
            ## Comment line below to remove BHE safety - Don't blame me if you wipe your instance ##
            #if($(BHSession|? x).edition -eq 'BHE'){RETURN 'Computer Says No... ¯\_(ツ)_/¯'}
            #DEBUG
            $($ClearItem|Convertto-Json)
            # Clear DB
            #BHAPI api/v2/clear-database POST $($ClearItem|Convertto-Json)
            }
        }}
    End{}
    }
#End

## BloodHound Operator - BHNode
# Search-BHNode
# Get-BHNode
# Get-BHNodeGroup
# New-BHNodeGroup
# Set-BHNodeGroup
# Remove-BHNodeGroup
# New-BHNodeGroupSelector
# Remove-BHNodeGroupSelector


enum BHEntityType{
    # AD
    Base
    Domain
    Container
    OU
    Group
    User
    Computer
    GPO
    # ADCS
    AIACA
    RootCA
    EnterpriseCA
    NTAuthStore
    CertTemplate
    # AZ
    AZBase
    AZTenant
    AZManagementGroup
    AZSubscription
    AZResourceGroup
    AZVM
    AZVMScaleSet
    AZAutomationAccount
    AZLogicApp
    AZFunctionApp
    AZManagedCluster
    AZResourceNode
    AZContainerRegistry
    AZKeyVault
    AZWebApp
    # AAD
    AZApp
    AZServicePrincipal
    AZUser
    AZGroup
    AZRole
    AZDevice
    ## Add OG here...
    }
#End



################################################ Search-BHNode

<#
.Synopsis
    Search BloodHound Node
.DESCRIPTION
    Search BloodHound Node
.EXAMPLE
    BHSearch user bob
#>
function Search-BHNode{
    [Alias('BHSearch')]
    Param(
        [Parameter(Mandatory=0,Position=0)][Alias('Type')][BHEntityType[]]$Label,
        [Parameter(Mandatory=0,Position=1)][String[]]$Keyword='-',
        [Parameter(Mandatory=0)][Int]$Limit=$($BHSession|? x|select -last 1).limit,
        [Parameter(Mandatory=0)][Switch]$Exact,
        [Parameter(Mandatory=0)][int[]]$SessionID=($BHSession|? x).id
        )
    foreach($SessID in $SessionID){Foreach($Key in $Keyword){
        $Key=$Key.replace(' ','+')
        $RL = if($exact){
            $Label = 'exact'
            "api/v2/graph-search?query=$Key"
            }
        else{"api/v2/search?q=$key"}
        if($Limit){$RL+="&limit=$Limit"}
        if($Label){Foreach($Lbl in $Label){Invoke-BHAPI "$RL&type=$lbl" -dot data -SessionID $SessID}}
        else{Invoke-BHAPI $RL -dot data -SessionID $SessID}
        }}
    }
#End



<#
function Search-BHNode{
    [Alias('BHSearch')]
    Param(
        [Parameter(Mandatory=0,Position=0)][Alias('Type')][BHEntityType[]]$Label,
        [Parameter(Mandatory=0,Position=1)][String[]]$Keyword='-',
        [Parameter(Mandatory=0)][Int]$Limit=$($BHSession|? x|select -last 1).limit,
        [Parameter(Mandatory=0)][Switch]$Exact
        )
    Foreach($Key in $Keyword){
        $Key=$Key.replace(' ','+')
        $RL = if($exact){
            $Label = 'exact'
            "api/v2/graph-search?query=$Key&limit=$limit"
            }
        else{"api/v2/search?q=$key&limit=$Limit"}
        if($Label){Foreach($Lbl in $Label){Invoke-BHAPI "$RL&type=$lbl" -dot data}}
        else{Invoke-BHAPI $RL -dot data}
        }
    }
#End
#>



################################################ Get-BHNode

<#
.SYNOPSIS
    Get BloodHound Node
.DESCRIPTION
    Get BloodHound Node
.EXAMPLE
    BHNode User -id <id>
.EXAMPLE
    BHNode -Search User alice
#><#
function Get-BHNode{
    [Alias('BHNode')]
        Param(
        [Parameter(Mandatory=1,Position=0,ParameterSetName='Search')]
        [Parameter(Mandatory=0,Position=0,ValueFromPipelineByPropertyName,ParameterSetName='ByID')][Alias('Type')][BHEntityType]$Label,
        [Parameter(Mandatory=1,Position=1,ValueFromPipeline,ValueFromPipelineByPropertyName,ParameterSetName='ByID')][Alias('ID','object_id')][String[]]$ObjectID,
        [Parameter(Mandatory=1,ParameterSetName='Search')][Switch]$Search,
        [Parameter(Mandatory=0,Position=1,ParameterSetName='Search')][String[]]$Keyword='-',
        [Parameter(Mandatory=0)][Alias('NoCount')][Switch]$PropOnly,
        [Parameter(Mandatory=0)][String]$Expand='data',
        [Parameter(Mandatory=0)][Switch]$AsPath,
        [Parameter(Mandatory=0)][Int]$Limit=$($BHSession|? x|select -last 1).limit,
        [Parameter(Mandatory=0)][Switch]$Cypher,
        [Parameter(Mandatory=0)][int[]]$SessionID=($BHSession|? x).id
        )
    DynamicParam{
        $Dico = New-Object Management.Automation.RuntimeDefinedParameterDictionary
        # Prep DynNamelist
        $DynList = Switch -regex ($Label){
            # AD
            ^Base$          {'Controllables'}
            ^Container$     {'Controllers'}
            ^Computer$      {'AdminRights','AdminUsers','ConstrainedDelegationRights','ConstrainedUsers','Controllables','Controllers','DCOMRights','DCOMUsers','GroupMemberships','PSRemoteRights','PSRemoteUsers','RDPRights','Sessions','SQLAdmins'}
            ^Domain$        {'Computers','Controllers','DCSyncers','ForeignAdmins','ForeignGPOControllers','ForeignGroups','ForeignUsers','GPOs','Groups','IndoundTrusts','LinkedGPOs','OUs','OutboundTrusts','Users'}
            ^GPO$           {'Computers','Containers','Controllers','OUs','TierZero','Users'}
            ^Group$         {'AdminRights','Controllables','Controllers','DCMRights','Members','Memberships','PSRemoteRights','RDPRights','Sessions'}
            ^OU$            {'Computers','GPOs','Groups','Users'}
            ^User$          {'AdminRights','ConstrainedDelegationRights','Controllables','Controllers','DCOMRights','Memberships','PSRemoteRights','RDPRights','Sessions','SQLAdminRights'}
            # ADCS
            ^AIACA$        {'Controllers'}
            ^CertTemplate$ {'Controllers'}
            ^EnterpriseCA$ {'Controllers'}
            ^NTAuthStore$  {'Controllers'}
            ^RootCA$       {'Controllers'}
            # AZ <-------------------------------------- ToDo: List Items
            ^AZBase$ {'InboundControl'}
            ^AZTenant$ {
                'Users',
                'Groups',
                'ManagementGroups',
                'Subscriptions',
                'ResourceGroups',
                'VMs',
                'ManagedClusters',
                'VMScaleSets',
                'ContainerRegistries',
                'WebApps',
                'AutomationAccounts',
                'KeyVaults',
                'FunctionApps',
                'LogicApps',
                'AppRegistrations',
                'ServicePrincipals',
                'Devices',
                'InboundControl'
                }
            ^AZManagementGroup$ {
                'Users',
                'Groups',
                'ManagementGroups',
                'Subscriptions',
                'ResourceGroups',
                'VMs',
                'ManagedClusters',
                'VMScaleSets',
                'ContainerRegistries',
                'WebApps',
                'AutomationAccounts',
                'KeyVaults',
                'FunctionApps',
                'LogicApps',
                'AppRegistrations',
                'ServicePrincipals',
                'Devices',
                'InboundControl'
                }
            ^AZSubscription$ {
                'Users',
                'Groups',
                'ResourceGroups',
                'VMs',
                'ManagedClusters',
                'VMScaleSets',
                'ContainerRegistries',
                'WebApps',
                'AutomationAccounts',
                'KeyVaults',
                'FunctionApps',
                'LogicApps',
                'AppRegistrations',
                'ServicePrincipals',
                'Devices',
                'InboundControl'
                }
            ^AZResourceGroup$ {
                'Users',
                'Groups',
                'ResourceGroups',
                'VMs',
                'ManagedClusters',
                'VMScaleSets',
                'ContainerRegistries',
                'WebApps',
                'AutomationAccounts',
                'KeyVaults',
                'FunctionApps',
                'LogicApps',
                'AppRegistrations',
                'ServicePrincipals',
                'Devices',
                'InboundControl'}
            ^AZVM$                  {'LocalAdmin','InboundControl'}
            ^AZAutomationAccount$   {'InboundControl'}
            ^AZLogicApp$            {'InboundControl'}
            ^AZFunctionApp$         {'InboundControl'}
            ^AZWebApp$              {'InboundControl'}
            ^AZKeyVault$            {'InboundControl','KeyReaders','CertificateReaders','SecretReaders',,'AllReaders'}
            ^AZManagedCluster$      {'InboundControl'}
            ^AZVMScaleSet$          {'InboundControl'}
            ^AZContainerRegistry$   {'InboundControl'}
            # AZ AAD
            ^AZRole$                {'ActiveAssignments'}
            ^AZUser$                {'MemberOf','Roles','ExecutionPrivileges','OutboundControl','InboundControl'}
            ^AZGroup$               {'Members','MemberOf','Roles','InboundControl','OutboundControl'}
            ^AZServicePrincipal$    {'Roles','InboundControl','OutboundControl','InboundAppRole','OutboundAppRole'}
            ^AZApp$                 {'InboundControl'}
            ^AZDevice$              {'LocalAdmin','InboundControl'}
            #Default{}
            }
        # Prep DynP
        $DynP = DynP -Name 'List' -Type 'String' -Mandat 0 -VSet $DynList
        # DynP to Dico
        $Dico.Add("List",$DynP)
        # Return Dico
        Return $Dico
        }
    Begin{Foreach($SessID in $SessionID){if($Search){foreach($Key in $Keyword){Search-BHNode $Label $Key -SessionID $SessID -limit $Limit |%{
            if($DynP.Value){$_|Get-BHNode $Label -List $DynP.Value -Expand $Expand -AsPath:$ASPath -Cypher:$Cypher -limit $Limit -PropOnly:$PropOnly -SessionID $SessID}
            else{$_|Get-BHNode $Label -Expand $Expand -AsPath:$ASPath -Cypher:$Cypher -limit $Limit -PropOnly:$PropOnly -SessionID $SessID}
            }}}}}
    Process{Foreach($SessID in $SessionID){Foreach($ObjID in $ObjectID){
        $URL = Switch -regex ($Label){
            # AD
            ^Base$      {"api/v2/base/$ObjID"}
            ^Container$ {"api/v2/containers/$ObjID"}
            ^Computer$  {"api/v2/computers/$ObjID"}
            ^Domain$    {"api/v2/domains/$ObjID"}
            ^GPO$       {"api/v2/gpos/$ObjID"}
            ^Group$     {"api/v2/groups/$ObjID"}
            ^OU$        {"api/v2/ous/$ObjID"}
            ^User$      {"api/v2/users/$ObjID"}
            # ADCS
            ^AIACA$        {"api/v2/aiacas/$ObjID"}
            ^CertTemplate$ {"api/v2/certtemplates/$ObjID"}
            ^EnterpriseCA$ {"api/v2/enterprisecas/$ObjID"}
            ^NTAuthStore$  {"api/v2/ntauthstores/$ObjID"}
            ^RootCA$       {"api/v2/rootcas/$ObjID"}
            # AZ
            ^AZ {$lbl = Switch($label){
                    AZBase                  {'az-base'}
                    AZApp                   {'applications'}
                    AZAutomationAccount     {'automation-accounts'}
                    AZContainerRegistry     {'container-registries'}
                    AZFunctionApp           {'function-apps'}
                    AZKeyVault              {'key-vaults'}
                    AZLogicApp              {'logic-apps'}
                    AZManagementGroup       {'management-groups'}
                    AZManagedCluster        {'managed-clusters'}
                    AZResourceGroup         {'resource-groups'}
                    AZServicePrincipal      {'service-principals'}
                    AZVMScaleSet            {'vm-scale-sets'}
                    AZWebApp                {'web-apps'}
                    Default{"$("$label".tolower()-replace"^az")s"}
                    }
                "api/v2/azure/${lbl}?object_id=$($ObjID-replace"/",'%2F')"
                }
            Default{"api/v2/base/$ObjID"}
            }
        $URL += Switch($DynP.value){
            # AD+
            AdminRights                  {'/admin-rights'}
            AdminUsers                   {'/admin-users'}
            Computers                    {'/computers'}
            ConstrainedDelegationRights  {'/constrained-delegation-rights'}
            ConstrainedUsers             {'/contrained-user'}
            Controllables                {'/controllables'}
            Controllers                  {'/controllers'}
            DCOMRights                   {'/dcom-rights'}
            DCOMUsers                    {'/dcom-users'}
            DCSyncers                    {'/dc-syncers'}
            ForeignAdmins                {'/foregin-admins'}
            ForeignGPOControllers        {'/foregin-gpo-contollers'}
            ForeignGroups                {'/foreign-groups'}
            ForeignUsers                 {'/foreign-users'}
            GPOs                         {'/gpo'}
            GroupMemberships             {'/group-memberships'}
            Groups                       {$(if($Label -match '^AZ'){'&related_entity_type=descendent-groups'}else{'/groups'})}
            IndoundTrusts                {'/indbound-trusts'}
            LinkedGPOs                   {'/linked-gpos'}
            Members                      {$(if($Label -match '^AZ'){'&related_entity_type=group-members'}else{'/members'})}
            Memberships                  {'/memberships'}
            OUs                          {'/ous'}
            OutboundTrusts               {'/outboud-trusts'}
            PSRemoteRights               {'/ps-remote-rights'}
            PSRemoteUsers                {'/ps-remote-users'}
            RDPRights                    {'/rdp-rights'}
            RDPUsers                     {'/rdp-users'}
            Sessions                     {'/sessions'}
            SQLAdminRights               {'/sql-admin-rights'}
            SQLAdmins                    {'/sql-admins'}
            TierZero                     {'/tier-zero'}
            Users                        {$(if($Label -match '^AZ'){'&related_entity_type=descendent-users'}else{'/users'})}
            ## AZ
            # Descendents
            AppRegistrations             {'&related_entity_type=descendent-applications'}
            ServicePrincipals            {'&related_entity_type=descendent-service-principals'}
            Devices                      {'&related_entity_type=descendent-devices'}
            ManagementGroups             {'&related_entity_type=descendent-management-groups'}
            Subscriptions                {'&related_entity_type=descendent-subscriptions'}
            ResourceGroups               {'&related_entity_type=descendent-resource-groups'}
            AutomationAccounts           {'&related_entity_type=descendent-automation-accounts'}
            VMs                          {'&related_entity_type=descendent-vms'}
            ManagedClusters              {'&related_entity_type=descendent-managed-clusters'}
            VMScaleSets                  {'&related_entity_type=descendent-vm-scale-sets'}
            ContainerRegistries          {'&related_entity_type=descendent-container-registries'}
            FunctionApps                 {'&related_entity_type=descendent-function-apps'}
            LogicApps                    {'&related_entity_type=descendent-logic-apps'}
            WebApps                      {'&related_entity_type=descendent-web-apps'}
            KeyVaults                    {'&related_entity_type=descendent-key-vaults'}
            # Other
            InboundControl               {'&related_entity_type=inbound-control'}
            OutboundControl              {'&related_entity_type=outbound-control'}
            ActiveAssignments            {'&related_entity_type=active-assignments'}
            Roles                        {'&related_entity_type=roles'}
            MemberOf                     {'&related_entity_type=group-membership'}
            ExecutionPrivileges          {'&related_entity_type=outbound-execution-privileges'}
            InboundAppRole               {'&related_entity_type=inbound-abusable-app-role-asignments'} # /!\ Not Tested
            OutboundAppRole              {'&related_entity_type=outbound-abusable-app-role-asignments'} # /!\ Not Tested
            LocalAdmins                  {'&related_entity_type=inbound-execution-privileges'} # /!\ Not Tested
            #PimAssignments               {}<------------- /!\ Check
            Default                      {}
            }
        $URL+=if($URL -match 'azure'){"&limit=$Limit"}else{"?limit=$Limit"}
        if($PropOnly){$URL+="&counts=false"}
        $Obj = Invoke-BHAPI $URL -expand $Expand -SessionID $SessID
        if($DynP.Value){if($Obj -AND $AsPath){
            Switch($DynP.Value){
                AdminRights                  {$SrcID=$ObjID;$TgtID=$Obj.ObjectID;$Fltr=':MemberOf|AdminTo'}
                AdminUsers                   {$SrcID=$Obj.objectID;$TgtID=$ObjID;$Fltr=':MemberOf|AdminTo'}
                Computers                    {$SrcID=$ObjID;$TgtID=$Obj.ObjectID;$Fltr=':Contains'}
                ConstrainedDelegationRights  {$SrcID=$ObjID;$TgtID=$Obj.ObjectID;$Fltr=$Null} 
                ConstrainedUsers             {$SrcID=$Obj.objectID;$TgtID=$ObjID;$Fltr=$Null}
                Controllables                {$SrcID=$ObjID;$TgtID=$Obj.ObjectID;$Fltr=$Null}
                Controllers                  {$SrcID=$Obj.objectID;$TgtID=$ObjID;$Fltr=$Null}
                DCOMRights                   {$SrcID=$ObjID;$TgtID=$Obj.ObjectID;$Fltr=':MemberOf|ExecuteDCOM'}
                DCOMUsers                    {$SrcID=$Obj.objectID;$TgtID=$ObjID;$Fltr=':MemberOf|ExecuteDCOM'}
                DCSyncers                    {$SrcID=$Obj.objectID;$TgtID=$ObjID;$Fltr=':DCSync|SyncLAPSPassword'}
                ForeignAdmins                {$SrcID=$ObjID;$TgtID=$Obj.ObjectID;$Fltr=$Null}
                ForeignGPOControllers        {$SrcID=$Obj.objectID;$TgtID=$ObjID;$Fltr=$Null}
                ForeignGroups                {$SrcID=$Obj.objectID;$TgtID=$ObjID;$Fltr=$Null}
                ForeignUsers                 {$SrcID=$Obj.objectID;$TgtID=$ObjID;$Fltr=$Null}
                GPOs                         {$SrcID=$ObjID;$TgtID=$Obj.ObjectID;$Fltr=':Contains'}
                GroupMemberships             {$SrcID=$ObjID;$TgtID=$Obj.ObjectID;$Fltr=':MemberOf'}
                Groups                       {if($URL -match 'azure'){$SrcID=$ObjID;$TgtID=$Obj.props.ObjectID;$Fltr=':AZContains'}
                                                else{$SrcID=$ObjID;$TgtID=$Obj.ObjectID;$Fltr=':Contains'}
                                                }
                IndoundTrusts                {$SrcID=$Obj.objectID;$TgtID=$ObjID;$Fltr=':TrustedBy'}
                LinkedGPOs                   {$SrcID=$Obj.objectID;$TgtID=$ObjID;$Fltr=':GPLink|Contains'}
                Members                      {if($URL -match 'azure'){$SrcID=$ObjID;$TgtID=$Obj.props.ObjectID;$Fltr=':AZMembers'}
                                                else{$SrcID=$Obj.objectID;$TgtID=$ObjID;$Fltr=':MemberOf'}
                                                }
                Memberships                  {$SrcID=$ObjID;$TgtID=$Obj.ObjectID;$Fltr=':MemberOf'}
                OUs                          {$SrcID=$ObjID;$TgtID=$Obj.ObjectID;$Fltr=':Contains'}
                OutboundTrusts               {$SrcID=$ObjID;$TgtID=$Obj.ObjectID;$Fltr=':TrustedBy'}
                PSRemoteRights               {$SrcID=$ObjID;$TgtID=$Obj.ObjectID;$Fltr=':MemberOf|CanPSRemote'}
                PSRemoteUsers                {$SrcID=$Obj.objectID;$TgtID=$ObjID;$Fltr=':MemberOf|CanPSRemote'}
                RDPRights                    {$SrcID=$ObjID;$TgtID=$Obj.ObjectID;$Fltr=':MemberOf|CanRDP'}
                RDPUsers                     {$SrcID=$ObjID;$TgtID=$Obj.ObjectID;$Fltr=':MemberOf|CanRDP'}
                Sessions                     {Switch($Label){Computer{$SrcID=$ObjID;$TgtID=$Obj.ObjectID}Default{$SrcID=$Obj.objectID;$TgtID=$ObjID}};$Fltr='HasSession'}
                SQLAdminRights               {$SrcID=$ObjID;$TgtID=$Obj.ObjectID;$Fltr=':MemberOf|SQLAdmin'}
                SQLAdmins                    {$SrcID=$Obj.objectID;$TgtID=$ObjID;$Fltr=':MemberOf|SQLAdmin'}
                TierZero                     {$SrcID=$ObjID;$TgtID=$Obj.ObjectID;$Fltr=':Contains'}
                Users                        {if($URL -match 'azure'){$SrcID=$ObjID;$TgtID=$Null;$Fltr=':AZContains'}
                                                else{$SrcID=$ObjID;$TgtID=$Obj.ObjectID;$Fltr=':Contains'}
                                                }
                ## ToDo: Azure Related entities -AsPath <--------------------------------------------------- /!\
                # Descendents
                AppRegistrations             {$SrcID=$ObjID;$TgtID=$Obj.props.ObjectID;$Fltr=':AZContains'}
                ServicePrincipals            {$SrcID=$ObjID;$TgtID=$Obj.props.ObjectID;$Fltr=':AZContains'}
                Devices                      {$SrcID=$ObjID;$TgtID=$Obj.props.ObjectID;$Fltr=':AZContains'}
                ManagementGroups             {$SrcID=$ObjID;$TgtID=$Obj.props.ObjectID;$Fltr=':AZContains'}
                Subscriptions                {$SrcID=$ObjID;$TgtID=$Obj.props.ObjectID;$Fltr=':AZContains'}
                ResourceGroups               {$SrcID=$ObjID;$TgtID=$Obj.props.ObjectID;$Fltr=':AZContains'}
                AutomationAccounts           {$SrcID=$ObjID;$TgtID=$Obj.props.ObjectID;$Fltr=':AZContains'}
                VMs                          {$SrcID=$ObjID;$TgtID=$Obj.props.ObjectID;$Fltr=':AZContains'}
                ManagedClusters              {$SrcID=$ObjID;$TgtID=$Obj.props.ObjectID;$Fltr=':AZContains'}
                VMScaleSets                  {$SrcID=$ObjID;$TgtID=$Obj.props.ObjectID;$Fltr=':AZContains'}
                ContainerRegistries          {$SrcID=$ObjID;$TgtID=$Obj.props.ObjectID;$Fltr=':AZContains'}
                FunctionApps                 {$SrcID=$ObjID;$TgtID=$Obj.props.ObjectID;$Fltr=':AZContains'}
                LogicApps                    {$SrcID=$ObjID;$TgtID=$Obj.props.ObjectID;$Fltr=':AZContains'}
                WebApps                      {$SrcID=$ObjID;$TgtID=$Obj.props.ObjectID;$Fltr=':AZContains'}
                KeyVaults                    {$SrcID=$ObjID;$TgtID=$Obj.props.ObjectID;$Fltr=':AZContains'}
                # Other
                InboundControl               {}
                OutboundControl              {}
                ActiveAssignments            {}
                Roles                        {}
                MemberOf                     {}
                ExecutionPrivileges          {}
                InboundAppRole               {}
                OutboundAppRole              {}
                LocalAdmins                  {}
                #PimAssignments              {}
                Default                      {
                    if($Url -match 'azure'){$SrcID=$ObjID;$TgtID=$Obj.props.ObjectID;$Fltr=':AZContains'}
                    else{$SrcID=$ObjID;$TgtID=$Obj.ObjectID;$Fltr=$Null}
                    }
                }
            $Query = (Get-BHPath -SourceId $SrcID -TargetID $TgtID -Edge $Fltr -limit $($null) -orderby "LENGTH(p)"-Cypher).trim()
            $Obj = if($Cypher){if(($BHSession|? x|Select -last 1).CypherClip){$Query| Set-Clipboard};RETURN $Query}else{
                Get-BHPath $Query #-SessionID $SessID
                }
            #$Obj=$CypherQ
            }}
        if($Obj){if($DynP.IsSet){if($Obj.props -AND $Obj.kind -AND $PropOnly){$Obj.props}else{$Obj}}else{Format-BHNode $Obj -PropOnly:$PropOnly}}
        }}}
    End{}
    }
#End
#>

<#
.SYNOPSIS
    Get BloodHound Node
.DESCRIPTION
    Get BloodHound Node
.EXAMPLE
    BHNode User -id <id>
.EXAMPLE
    BHNode -Search User alice
.EXAMPLE
    bhnode -search user yoda -list controllers
.EXAMPLE
    bhnode -search user yoda -list controllers -AsPath [-Cypher] # EXPERIMENTAL - DO NOT TRUST OUTPUT
#>
function Get-BHNode{
    [Alias('BHNode')]
        Param(
        [Parameter(Mandatory=1,Position=0,ParameterSetName='Search')]
        [Parameter(Mandatory=0,Position=0,ValueFromPipelineByPropertyName,ParameterSetName='ByID')][Alias('Type')][BHEntityType]$Label,
        [Parameter(Mandatory=1,Position=1,ValueFromPipeline,ValueFromPipelineByPropertyName,ParameterSetName='ByID')][Alias('ID','object_id')][String[]]$ObjectID,
        [Parameter(Mandatory=1,ParameterSetName='Search')][Switch]$Search,
        [Parameter(Mandatory=0,Position=1,ParameterSetName='Search')][String[]]$Keyword='-',
        [Parameter(Mandatory=0)][Alias('NoCount')][Switch]$PropOnly,
        [Parameter(Mandatory=0)][String]$Expand='data',
        [Parameter(Mandatory=0)][Switch]$AsPath,
        [Parameter(Mandatory=0)][Int]$Limit=$($BHSession|? x|select -last 1).limit,
        [Parameter(Mandatory=0)][Switch]$Cypher,
        [Parameter(Mandatory=0)][int[]]$SessionID=($BHSession|? x).id
        )
    DynamicParam{
        $Dico = New-Object Management.Automation.RuntimeDefinedParameterDictionary
        # Prep DynNamelist
        $DynList = Switch -regex ($Label){
            # AD
            ^Base$          {'Controllables'}
            ^Container$     {'Controllers'}
            ^Computer$      {'AdminRights','AdminUsers','ConstrainedDelegationRights','ConstrainedUsers','Controllables','Controllers','DCOMRights','DCOMUsers','GroupMemberships','PSRemoteRights','PSRemoteUsers','RDPRights','Sessions','SQLAdmins'}
            ^Domain$        {'Computers','Controllers','DCSyncers','ForeignAdmins','ForeignGPOControllers','ForeignGroups','ForeignUsers','GPOs','Groups','IndoundTrusts','LinkedGPOs','OUs','OutboundTrusts','Users'<#,'TierZero'#>}
            ^GPO$           {'Computers','Containers','Controllers','OUs','TierZero','Users'}
            ^Group$         {'AdminRights','Controllables','Controllers','DCMRights','Members','Memberships','PSRemoteRights','RDPRights','Sessions'}
            ^OU$            {'Computers','GPOs','Groups','Users'}
            ^User$          {'AdminRights','ConstrainedDelegationRights','Controllables','Controllers','DCOMRights','Memberships','PSRemoteRights','RDPRights','Sessions','SQLAdminRights'}
            # ADCS
            ^AIACA$        {'Controllers'}
            ^CertTemplate$ {'Controllers'}
            ^EnterpriseCA$ {'Controllers'}
            ^NTAuthStore$  {'Controllers'}
            ^RootCA$       {'Controllers'}
            # AZ <-------------------------------------- ToDo: List Items
            ^AZBase$ {'InboundControl'}
            ^AZTenant$ {
                'Users',
                'Groups',
                'ManagementGroups',
                'Subscriptions',
                'ResourceGroups',
                'VMs',
                'ManagedClusters',
                'VMScaleSets',
                'ContainerRegistries',
                'WebApps',
                'AutomationAccounts',
                'KeyVaults',
                'FunctionApps',
                'LogicApps',
                'AppRegistrations',
                'ServicePrincipals',
                'Devices',
                'InboundControl'
                }
            ^AZManagementGroup$ {
                'Users',
                'Groups',
                'ManagementGroups',
                'Subscriptions',
                'ResourceGroups',
                'VMs',
                'ManagedClusters',
                'VMScaleSets',
                'ContainerRegistries',
                'WebApps',
                'AutomationAccounts',
                'KeyVaults',
                'FunctionApps',
                'LogicApps',
                'AppRegistrations',
                'ServicePrincipals',
                'Devices',
                'InboundControl'
                }
            ^AZSubscription$ {
                'Users',
                'Groups',
                'ResourceGroups',
                'VMs',
                'ManagedClusters',
                'VMScaleSets',
                'ContainerRegistries',
                'WebApps',
                'AutomationAccounts',
                'KeyVaults',
                'FunctionApps',
                'LogicApps',
                'AppRegistrations',
                'ServicePrincipals',
                'Devices',
                'InboundControl'
                }
            ^AZResourceGroup$ {
                'Users',
                'Groups',
                'ResourceGroups',
                'VMs',
                'ManagedClusters',
                'VMScaleSets',
                'ContainerRegistries',
                'WebApps',
                'AutomationAccounts',
                'KeyVaults',
                'FunctionApps',
                'LogicApps',
                'AppRegistrations',
                'ServicePrincipals',
                'Devices',
                'InboundControl'}
            ^AZVM$                  {'LocalAdmins','InboundControl'}
            ^AZAutomationAccount$   {'InboundControl'}
            ^AZLogicApp$            {'InboundControl'}
            ^AZFunctionApp$         {'InboundControl'}
            ^AZWebApp$              {'InboundControl'}
            ^AZKeyVault$            {'InboundControl','KeyReaders','CertificateReaders','SecretReaders',,'AllReaders'}
            ^AZManagedCluster$      {'InboundControl'}
            ^AZVMScaleSet$          {'InboundControl'}
            ^AZContainerRegistry$   {'InboundControl'}
            # AZ AAD
            ^AZRole$                {'ActiveAssignments'<#,'PimAssignments'#>}
            ^AZUser$                {'MemberOf','Roles','ExecutionPrivileges','OutboundControl','InboundControl'}
            ^AZGroup$               {'Members','MemberOf','Roles','InboundControl','OutboundControl'}
            ^AZServicePrincipal$    {'Roles','InboundControl','OutboundControl','InboundAppRole','OutboundAppRole'}
            ^AZApp$                 {'InboundControl'}
            ^AZDevice$              {'LocalAdmin','InboundControl'}
            #Default{}
            }
        # Prep DynP
        $DynP = DynP -Name 'List' -Type 'String' -Mandat 0 -VSet $DynList
        # DynP to Dico
        $Dico.Add("List",$DynP)
        # Return Dico
        Return $Dico
        }
    Begin{Foreach($SessID in $SessionID){if($Search){foreach($Key in $Keyword){Search-BHNode $Label $Key -SessionID $SessID -limit $Limit |%{
            if($DynP.Value){$_|Get-BHNode $Label -List $DynP.Value -Expand $Expand -AsPath:$ASPath -Cypher:$Cypher -limit $Null -PropOnly:$PropOnly -SessionID $SessID}
            else{$_|Get-BHNode $Label -Expand $Expand -AsPath:$ASPath -Cypher:$Cypher -limit $Null -PropOnly:$PropOnly -SessionID $SessID}
            }}}}}
    Process{Foreach($SessID in $SessionID){Foreach($ObjID in $ObjectID){
        $URL = Switch -regex ($Label){
            # AD
            ^Base$      {"api/v2/base/$ObjID"}
            ^Container$ {"api/v2/containers/$ObjID"}
            ^Computer$  {"api/v2/computers/$ObjID"}
            ^Domain$    {"api/v2/domains/$ObjID"}
            ^GPO$       {"api/v2/gpos/$ObjID"}
            ^Group$     {"api/v2/groups/$ObjID"}
            ^OU$        {"api/v2/ous/$ObjID"}
            ^User$      {"api/v2/users/$ObjID"}
            # ADCS
            ^AIACA$        {"api/v2/aiacas/$ObjID"}
            ^CertTemplate$ {"api/v2/certtemplates/$ObjID"}
            ^EnterpriseCA$ {"api/v2/enterprisecas/$ObjID"}
            ^NTAuthStore$  {"api/v2/ntauthstores/$ObjID"}
            ^RootCA$       {"api/v2/rootcas/$ObjID"}
            # AZ
            ^AZ {$lbl = Switch($label){
                    AZBase                  {'az-base'}
                    AZApp                   {'applications'}
                    AZAutomationAccount     {'automation-accounts'}
                    AZContainerRegistry     {'container-registries'}
                    AZFunctionApp           {'function-apps'}
                    AZKeyVault              {'key-vaults'}
                    AZLogicApp              {'logic-apps'}
                    AZManagementGroup       {'management-groups'}
                    AZManagedCluster        {'managed-clusters'}
                    AZResourceGroup         {'resource-groups'}
                    AZServicePrincipal      {'service-principals'}
                    AZVMScaleSet            {'vm-scale-sets'}
                    AZWebApp                {'web-apps'}
                    Default{"$("$label".tolower()-replace"^az")s"}
                    }
                "api/v2/azure/${lbl}?object_id=$($ObjID-replace"/",'%2F')"
                }
            Default{"api/v2/base/$ObjID"}
            }
        $URL += Switch($DynP.value){
            # AD+
            AdminRights                  {'/admin-rights'}
            AdminUsers                   {'/admin-users'}
            Computers                    {'/computers'}
            ConstrainedDelegationRights  {'/constrained-delegation-rights'}
            ConstrainedUsers             {'/constrained-users'}
            Controllables                {'/controllables'}
            Controllers                  {'/controllers'}
            DCOMRights                   {'/dcom-rights'}
            DCOMUsers                    {'/dcom-users'}
            DCSyncers                    {'/dc-syncers'}
            ForeignAdmins                {'/foreign-admins'}
            ForeignGPOControllers        {'/foreign-gpo-contollers'}
            ForeignGroups                {'/foreign-groups'}
            ForeignUsers                 {'/foreign-users'}
            GPOs                         {'/gpos'}
            GroupMemberships             {'/group-memberships'}
            Groups                       {$(if($Label -match '^AZ'){'&related_entity_type=descendent-groups'}else{'/groups'})}
            IndoundTrusts                {'/indbound-trusts'}
            LinkedGPOs                   {'/linked-gpos'}
            Members                      {$(if($Label -match '^AZ'){'&related_entity_type=group-members'}else{'/members'})}
            Memberships                  {'/memberships'}
            OUs                          {'/ous'}
            OutboundTrusts               {'/outboud-trusts'}
            PSRemoteRights               {'/ps-remote-rights'}
            PSRemoteUsers                {'/ps-remote-users'}
            RDPRights                    {'/rdp-rights'}
            RDPUsers                     {'/rdp-users'}
            Sessions                     {'/sessions'}
            SQLAdminRights               {'/sql-admin-rights'}
            SQLAdmins                    {'/sql-admins'}
            TierZero                     {'/tier-zero'}
            Users                        {$(if($Label -match '^AZ'){'&related_entity_type=descendent-users'}else{'/users'})}
            ## AZ
            # Descendents
            AppRegistrations             {'&related_entity_type=descendent-applications'}
            ServicePrincipals            {'&related_entity_type=descendent-service-principals'}
            Devices                      {'&related_entity_type=descendent-devices'}
            ManagementGroups             {'&related_entity_type=descendent-management-groups'}
            Subscriptions                {'&related_entity_type=descendent-subscriptions'}
            ResourceGroups               {'&related_entity_type=descendent-resource-groups'}
            AutomationAccounts           {'&related_entity_type=descendent-automation-accounts'}
            VMs                          {'&related_entity_type=descendent-virtual-machines'}
            ManagedClusters              {'&related_entity_type=descendent-managed-clusters'}
            VMScaleSets                  {'&related_entity_type=descendent-vm-scale-sets'}
            ContainerRegistries          {'&related_entity_type=descendent-container-registries'}
            FunctionApps                 {'&related_entity_type=descendent-function-apps'}
            LogicApps                    {'&related_entity_type=descendent-logic-apps'}
            WebApps                      {'&related_entity_type=descendent-web-apps'}
            KeyVaults                    {'&related_entity_type=descendent-key-vaults'}
            # Other
            InboundControl               {'&related_entity_type=inbound-control'}
            OutboundControl              {'&related_entity_type=outbound-control'}
            ActiveAssignments            {'&related_entity_type=active-assignments'}
            Roles                        {'&related_entity_type=roles'}
            MemberOf                     {'&related_entity_type=group-membership'}
            ExecutionPrivileges          {'&related_entity_type=outbound-execution-privileges'}
            InboundAppRole               {'&related_entity_type=inbound-abusable-app-role-asignments'} # /!\ Not Tested
            OutboundAppRole              {'&related_entity_type=outbound-abusable-app-role-asignments'} # /!\ Not Tested
            LocalAdmins                  {'&related_entity_type=inbound-execution-privileges'} # /!\ Not Tested
            #PimAssignments               {}<------------- /!\ Check
            KeyReaders                   {'&related_entity_type=key-readers'}
            SecretReaders                {'&related_entity_type=secret-readers'}
            CertificateReaders           {'&related_entity_type=certificate-readers'}
            AllReaders                   {'&related_entity_type=all-readers'}
            #Default                      {}
            }
        if($Limit){$URL+=if($URL -match 'azure'){"&limit=$Limit"}else{"?limit=$Limit"}}
        if($PropOnly){$URL+="&counts=false"}
        if($DynP.Value -AND ($AsPath -OR $Cypher)){
            # EdgeList
            # AD
            $ADAttackEdge = (Get-BHPathfilter -ListAll | ? Platform -eq AD).edge
            # AZ
            $AZAttackEdge = (Get-BHPathfilter -ListAll | ? Platform -eq AZ).edge
            $AZExecEdge = 'AZVMAdminLogin',
                'AZVMContributor',
                'AZAvereContributor',
                'AZWebsiteContributor',
                'AZContributor',
                'AZExecuteCommand'
            $AZAppAbuseEdge = 'AZApplicationReadWriteAll',
                'AZAppRoleAssignmentReadWriteAll',
                'AZDirectoryReadWriteAll',
                'AZGroupReadWriteAll',
                'AZGroupMemberReadWriteAll',
                'AZRoleManagementReadWriteDirectory',
                'AZServicePrincipalEndpointReadWriteAll'
            $AZControlEdge=	'AZAvereContributor',
                'AZContributor',
                'AZOwner',
                'AZVMContributor',
                'AZAutomationContributor',
                'AZKeyVaultContributor',
                'AZAddMembers',
                'AZAddSecret',
                'AZExecuteCommand',
                'AZGlobalAdmin',
                'AZGrant',
                'AZGrantSelf',
                'AZPrivilegedRoleAdmin',
                'AZResetPassword',
                'AZUserAccessAdministrator',
                'AZOwns',
                'AZCloudAppAdmin',
                'AZAppAdmin',
                'AZAddOwner',
                'AZManagedIdentity',
                'AZAKSContributor',
                'AZWebsiteContributor',
                'AZLogicAppContributor',
                'AZAZMGAddMember',
                'AZAZMGAddOwner',
                'AZMGAddSecret',
                'AZMGGrantAppRoles',
                'AZMGGrantRole'
            # Query /!\ EXPERIMENTAL FEATURE /!\
            $Query = Switch($DynP.Value){
                AdminRights                  {"MATCH p=(:$Label{objectid:'$objID'})-[:MemberOf|AdminTo*1..]->(x:Computer)"}
                AdminUsers                   {"MATCH p=shortestPath((x:User)-[:MemberOf|AdminTo*1..]->(:$Label{objectid:'$objID'}))"} # Shortest??
                Computers                    {"MATCH p=(:$Label{objectid:'$objID'})-[:Contains*1..]->(x:Computer)"}
                ConstrainedDelegationRights  {"MATCH p=(:$Label{objectid:'$objID'})-[:MemberOf|AllowedToDelegate*1..]->(x:Computer)"}
                ConstrainedUsers             {"MATCH p=(x:Base)-[:MemberOf|AllowedToDelegate*1..]->(:$Label{objectid:'$objID'})"}
                Controllables                {"MATCH p=(:$Label{objectid:'$objID'})-[:$($ADAttackEdge-join'|')*1..]->(x:Base)"}
                Controllers                  {"MATCH p=(x:Base)-[:$($ADAttackEdge-join'|')*1..]->(:$Label{objectid:'$objID'})"}
                DCOMRights                   {"MATCH p=(:$Label{objectid:'$objID'})-[:MemberOf|ExecuteDCOM*1..]->(x:Computer)"}
                DCOMUsers                    {"MATCH p=(x:Base)-[:MemberOf|ExecuteDCOM*1..]->(:$Label{objectid:'$objID'})"}
                DCSyncers                    {"MATCH p=(x:Base)-[:DCSync|SyncLAPSPassword]->(:$Label{objectid:'$ObjID'})"}
                ForeignAdmins                {"MATCH p=shortestPath((x:User)-[:MemberOf|AdminTo*1..]->(y:$Label{objectid:'$objID'})) WHERE x.domain<>y.domain"}
                ForeignGPOControllers        {<#ToDo#>}
                ForeignGroups                {<#ToDo#>}
                ForeignUsers                 {<#ToDo#>}
                GPOs                         {"MATCH p=(:$Label{objectid:'$ObjID'})<-[:GPLink|Contains*1..]-(x:GPO)"}
                GroupMemberships             {"MATCH p=(:$Label{objectid:'$ObjID'})-[:MemberOf*1..]->(x:Group)"}
                Groups                       {if($URL -match 'azure'){"MATCH p=(:$Label{objectid:'$ObjID'})-[:AZContains]->(x:AZGroup)"}
                                                else{"MATCH p=(:$Label{objectid:'$ObjID'})-[:Contains]->(x:Group)"}
                                                }
                IndoundTrusts                {"MATCH p=(:$Label{objectid:'$ObjID'})-[:TrustedBy*1..]->(x:Domain)"}
                LinkedGPOs                   {"MATCH p=(x:GPO)-[:GPLink|Contains*1..]->(:$Label{objectid:'$ObjID'})"}
                Members                      {if($URL -match 'azure'){"MATCH p=(:AZBase)-[:AZMemberOf*1..]->(:$Label{objectid:'$ObjID'})"}
                                                else{"MATCH p=(:Base)-[:MemberOf*1..]->(:$Label{objectid:'$ObjID'})"}
                                                }
                Memberships                  {"MATCH p=(:$Label{objectid:'$ObjID'})-[:MemberOf*1..]->(x:Group)"}
                OUs                          {"MATCH p=(:$Label{objectid:'$ObjID'})-[:Contains*1..]->(x:OU)"}
                OutboundTrusts               {"MATCH p=(x:Domain)-[:TrustedBy*1..]->(:$Label{objectid:'$ObjID'})"}
                PSRemoteRights               {"MATCH p=(:$Label{objectid:'$objID'})-[:MemberOf|CanPSRemote*1..]->(x:Computer)"}
                PSRemoteUsers                {"MATCH p=shortestPath((x:User)-[:MemberOf|CanPSRemote*1..]->(:$Label{objectid:'$objID'}))"}
                RDPRights                    {"MATCH p=(:$Label{objectid:'$objID'})-[:MemberOf|CanRDP*1..]->(x:Computer)"}
                RDPUsers                     {"MATCH p=shortestPath((x:User)-[:MemberOf|CanRDP*1..]->(:$Label{objectid:'$objID'}))"}
                Sessions                     {Switch($Label){
                                                Computer{"MATCH p=(:$Label{objectid:'$ObjID'})-[:HasSession]->(x:User)"}
                                                Default{"MATCH p=(:$Label{objectid:'$ObjID'})-[:MemberOf|HasSession*1..]->(x:User)"} # TEST /!\
                                                }}
                SQLAdminRights               {"MATCH p=(:$Label{objectid:'$objID'})-[:MemberOf|SQLAdmin*1..]->(x:Computer)"}
                SQLAdmins                    {"MATCH p=shortestPath((x:User)-[:MemberOf|SQLDamin*1..]->(:$Label{objectid:'$objID'}))"}
                TierZero                     {"MATCH p=(:$Label{objectid:'$ObjID'})-[:Contains]->(x:Base)`r`nWHERE x.system_tags CONTAINS 'admin_tier_0'"}
                Users                        {if($URL -match 'azure'){"MATCH p=(:$Label{objectid:'$ObjID'})-[:AZContains]->(x:AZUser)"}
                                                else{"MATCH p=(:$Label{objectid:'$ObjID'})-[:Contains*1..]->(x:User)"}
                                                }
                ## AZ - Descendents
                AppRegistrations             {"MATCH p=(:$Label{objectid:'$ObjID'})-[:AZContains]->(x:AZApp)"}
                ServicePrincipals            {"MATCH p=(:$Label{objectid:'$ObjID'})-[:AZContains]->(x:AZServicePrincipal)"}
                Devices                      {"MATCH p=(:$Label{objectid:'$ObjID'})-[:AZContains]->(x:AZDevice)"}
                ManagementGroups             {"MATCH p=(:$Label{objectid:'$ObjID'})-[:AZContains*1..]->(x:AZManagementGroup)"}
                Subscriptions                {if($Label -eq 'AZTenant'){"MATCH p=(:$Label{objectid:'$ObjID'})-[:AZContains]->(x:AZSubscription)"}
                                                else{"MATCH p=(:$Label{objectid:'$ObjID'})-[:AZContains*1..]->(x:AZSubscription)"}}
                ResourceGroups               {"MATCH p=(:$Label{objectid:'$ObjID'})-[:AZContains*1..]->(x:AZResourceGroup)"}
                AutomationAccounts           {"MATCH p=(:$Label{objectid:'$ObjID'})-[:AZContains*1..]->(x:AZAutomationAccount)"}
                VMs                          {"MATCH p=(:$Label{objectid:'$ObjID'})-[:AZContains*1..]->(x:AZVM)"}
                ManagedClusters              {"MATCH p=(:$Label{objectid:'$ObjID'})-[:AZContains*1..]->(x:AZManagedCluster)"}
                VMScaleSets                  {"MATCH p=(:$Label{objectid:'$ObjID'})-[:AZContains*1..]->(x:AZVMScaleSet)"}
                ContainerRegistries          {"MATCH p=(:$Label{objectid:'$ObjID'})-[:AZContains*1..]->(x:AZContainerRegistry)"}
                FunctionApps                 {"MATCH p=(:$Label{objectid:'$ObjID'})-[:AZContains*1..]->(x:AZFunctionApp)"}
                LogicApps                    {"MATCH p=(:$Label{objectid:'$ObjID'})-[:AZContains*1..]->(x:AZLogicApp)"}
                WebApps                      {"MATCH p=(:$Label{objectid:'$ObjID'})-[:AZContains*1..]->(x:AZWebApp)"}
                KeyVaults                    {"MATCH p=(:$Label{objectid:'$ObjID'})-[:AZContains*1..]->(x:AZKeyVault)"}
                # AZ - Other
                InboundControl               {"MATCH p=(x:AZBase)-[:AZMemberOf|$($AZControlEdge-join'|')*1..]->(:$Label{objectid:'$objID'})"}
                OutboundControl              {"MATCH p=(:$Label{objectid:'$objID'})-[:AZMemberOf|$($AZControlEdge-join'|')*1..]->(x:AZBase)"}
                ActiveAssignments            {"MATCH (x:AZBase)-[:AZHasRole]->(:$Label{objectid:'$ObjID'})"}# AZMemberOf??
                Roles                        {"MATCH p=(:$Label{objectid:'$ObjID'})-[:AZMemberOf|AZHasRole*1..]->(x:AZRole)"}
                MemberOf                     {"MATCH p=(:$Label{objectid:'$ObjID'})-[:AZMemberOf*1..]->(x:AZGroup)"}
                ExecutionPrivileges          {"MATCH p=(:$Label{objectid:'$ObjID'})-[:AZMemberOf|$($AZExecEdge-join'|')*1..]->(x:AZBase) WHERE NOT x:AZGroup"}
                InboundAppRole               {"MATCH p=(:$Label{objectid:'$ObjID'})-[:AZMemberOf|$($AZAppAbuseEdge-join'|')*1..]->(x:AZBase)"}
                OutboundAppRole              {"MATCH p=(x:AZBase)-[:$($AZAppAbuseEdge-join'|')*1..]->(:$Label{objectid:'$ObjID'})"}
                LocalAdmins                  {"MATCH (x:AZBase)-[:AZMemberOf|$($AZExecEdge-join'|')*1..]->(:$Label{objectid:'$ObjID'})"}
                #PimAssignments              {}
                KeyReaders                   {"MATCH p=(x:AZBase)-[:AZMemberOf|AZOwner|AZContributor|AZGetKeys*1..]->(:$Label{objectid:'$ObjID'})"}
                SecretReaders                {"MATCH p=(x:AZBase)-[:AZMemberOf|AZGetSecrets*1..]->(:$Label{objectid:'$ObjID'})"}
                CertificateReaders           {"MATCH p=(x:AZBase)-[:AZMemberOf|AZGetCertificates*1..]->(:$Label{objectid:'$ObjID'})"}
                AllReaders                   {"MATCH p=(x:AZBase)-[:AZMemberOf|AZGetKeys|AZGetSecrets|AZGetCertificates*1..]->(:$Label{objectid:'$ObjID'})"}
                #Default                     {}
                }
            #$Query = (Get-BHPath -SourceId $SrcID -TargetID $TgtID -Edge $Fltr -limit $($null) -orderby "LENGTH(p)"-Cypher).trim()
            #$Obj = if($Cypher){if(($BHSession|? x|Select -last 1).CypherClip){$Query| Set-Clipboard};RETURN $Query}else{
            #    #Get-BHPath $Query #-SessionID $SessID
            #    $Query
            #    }
            $Query+=if($AsPath){"`r`nRETURN p"}else{"`r`nRETURN x"}
            if($Limit){$Query = "$Query`r`nLIMIT $Limit"}
            $Obj = BHPath -Query $Query -Cypher:$Cypher
            }
        else{$Obj=if($Cypher){"MATCH (x:$Label{objectid:'$ObjID'}) RETURN x"}else{Invoke-BHAPI $URL -expand $Expand -SessionID $SessID}
            }
        if($Obj){if($DynP.IsSet){if($Obj.props -AND $Obj.kind -AND $PropOnly){$Obj.props}else{$Obj}}else{if($Cypher){$Obj}else{Format-BHNode $Obj -PropOnly:$PropOnly}}}
        }}}
    End{}
    }
#End


################################################ Get-BHNodeGroup

<#
.Synopsis
    Get BloodHound Asset Group
.DESCRIPTION
    Get BloodHound Asset Group
.EXAMPLE
    BHNodeGroup
#>
function Get-BHNodeGroup{
    [CmdletBinding(DefaultParameterSetName='List')]
    [Alias('BHNodeGroup')]
    Param(
        [Parameter(Mandatory=1,Position=0,ValueFromPipelineByPropertyName,ParameterSetName='Custom')]
        [Parameter(Mandatory=1,Position=0,ValueFromPipelineByPropertyName,ParameterSetName='Collection')]
        [Parameter(Mandatory=1,Position=0,ValueFromPipelineByPropertyName,ParameterSetName='Member')]
        [Parameter(Mandatory=0,Position=0,ValueFromPipelineByPropertyName,ParameterSetName='List')][String[]]$ID,
        [Parameter(Mandatory=1,ParameterSetName='Member')][Switch]$Member,
        [Parameter(Mandatory=0,ParameterSetName='Member')][Alias('TenantID','DomainID')][String]$EnvironmentID,
        [Parameter(Mandatory=0,ParameterSetName='Member')][Switch]$Count,
        #[Parameter(Mandatory=1,ParameterSetName='Collection')][Switch]$Collection, <------------- Broken?
        [Parameter(Mandatory=1,ParameterSetName='Custom')][Switch]$CustomCount,
        [Parameter(ParameterSetName='List')][Switch]$Selector
        )
    Begin{}
    Process{Foreach($ObjID in $ID){
        Switch($PSCmdlet.ParameterSetName){
            List{if($Selector){Invoke-BHAPI api/v2/asset-group-tags/$ObjID/selectors}
                else{Invoke-BHAPI api/v2/asset-groups/$ObjID -expand data}
                }
            Member{$qFilter = if($EnvironmentID){"environment_id=eq:$EnvironmentID"}else{$Null}
                if($Count){Invoke-BHAPI api/v2/asset-groups/$ObjID/members/counts -filter $qFilter -expand data}
                else{Invoke-BHAPI api/v2/asset-groups/$ObjID/members -filter $qFilter -expand data.members}
                }
            Collection{Invoke-BHAPI api/v2/asset-groups/$ObjID/collections -filter "limit=1" -expand data}
            Custom    {Invoke-BHAPI api/v2/asset-groups/$ObjID/custom-selectors -expand data}
            }}}
    End{if(-Not$ObjID){
        if($Selector){Invoke-BHAPI api/v2/asset-groups -expand data.asset_groups.selectors}
        else{Invoke-BHAPI api/v2/asset-groups -expand data.asset_groups}
        }}
    }
#End


################################################ New-BHNodeGroup

<#
.Synopsis
    New BloodHound Asset Group
.DESCRIPTION
    New BloodHound Asset Group
.EXAMPLE
    New-BHNodeGroup TestGroup
#>
function New-BHNodeGroup{
    Param(
        [Parameter(Position=0,Mandatory=1)][String]$Name,
        [Parameter(Position=1,Mandatory=0)][String]$Tag,
        [Parameter(Mandatory=0)][Switch]$PassThru
        )
    if(-Not$tag){$Tag=$Name.tolower().replace(' ','_')}
    $Body = @{name=$Name;tag=$Tag} | Convertto-Json
    $reply=Invoke-BHAPI api/v2/asset-groups -method POST -Body $Body -expand data
    if($PassThru){$Reply}
    }
#End


################################################ Remove-AssetGroup

<#
.Synopsis
    Remove BloodHound Asset Group
.DESCRIPTION
    Remove BloodHound Asset Group
.EXAMPLE
    Remove-BHNodeGroup 2
#>
function Remove-BHNodeGroup{
    Param(
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)][Int[]]$ID,
        [Parameter()][Switch]$Force
        )
    Begin{}
    Process{Foreach($GrpID in $ID){
        $GrpName = (Get-BHNodeGroup $GrpID).name
        if($force -OR (Confirm-Action "Delete Asset-Group $GrpName")){
            Invoke-BHAPI api/v2/asset-groups/$GrpID -Method DELETE
            }}}
    End{}###
    }
#End



################################################ Set-BHNodeGroup

<#
.Synopsis
    Set BloodHound Asset Group
.DESCRIPTION
    Set BloodHound Asset Group
.EXAMPLE
    Set-BHNodeGroup -ID $GroupID -Name $NewName
#>
function Set-BHNodeGroup{
        Param(
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)][Int]$ID,
        [Parameter(Mandatory=1)][String]$Name
        )
    Begin{}
    Process{foreach($GrpID in $ID){
        $Body = @{name=$Name} | Convertto-Json
        Invoke-BHAPI api/v2/asset-groups/$GrpID -Method PUT -Body $Body
        }}
    End{}
    }
#End


################ Selector

<#
function New-BHNodeGroupSelector{
    [Alias('New-BHSelector')]
    Param(
        [Parameter(Mandatory)]$NodeGroupID,
        [Parameter(Mandatory)][String]$SelectorName,
        #[Parameter(Mandatory)][String]$ObjectType,
        [Parameter(Mandatory)][String]$ObjectID,
        [Parameter()][Switch]$PassThru
        )
    $Body = @{
        action        = 'add'
        selector_name = $SelectorName
        sid           = $ObjectID
        }
    Invoke-BHAPI api/v2/asset-groups/$NodeGroupID/selectors -Method POST -Body (Convertto-Json @($Body)) -Expand data 
    }
#End
#>


<#
function Remove-BHNodeGroupSelector{
    [Alias('Remove-BHSelector')]
    Param(
        [Parameter(Mandatory)]$NodeGroupID,
        [Parameter(Mandatory)][String]$SelectorID,
        [Parameter()][Switch]$Force
        )
    if($Force -OR $(Confirm-Action "Delete Selector $SelectorID from Asset Group $NodeGroupID")){
        Invoke-BHAPI api/v2/asset-groups/$NodeGroupID/selectors/$SelectorID -Method DELETE
        }
    }
#End
#>

<#
.SYNOPSIS
    Add BHNode To BHNodeGroup
.DESCRIPTION
    Add BHNode To BHNodeGroup
.EXAMPLE
    BHSearch User alice | Add-BHNodeToNodeGroup -NodeGroupID 1
#>
function Add-BHNodeToNodeGroup{
    Param(
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)][Alias('NodeID')][String[]]$ObjectID,
        [Parameter(Mandatory)][Alias('GroupID')][Int]$NodeGroupID,
        [Parameter()][Switch]$Analyze,
        [Parameter()][Switch]$Force
        )
    Begin{NoMultiSession}
    Process{Foreach($NodeID in $ObjectID){if($Force -OR $(Confirm-Action "Add Object $NodeID to Asset Group $NodegroupID")){
        $AddSelect = @{
            selector_name = $NodeID
            sid = $NodeID
            action = 'add'
            }
        BHAPI api/v2/asset-groups/$NodeGroupID/selectors PUT "[$(@($AddSelect)|ConvertTo-Json -Depth 21)]" -expand data.added_selectors
        }}}
    End{if($Analyze){Start-BHDataAnalysis -verbose:$False}}
    }
#End


<#
.SYNOPSIS
    Remove BHNode From BHNodeGroup
.DESCRIPTION
    Remove BHNode From BHNodeGroup
.EXAMPLE
    BHSearch User alice | Remove-BHNodeFromNodeGroup -NodeGroupID 1
#>
function Remove-BHNodeFromNodeGroup{
    Param(
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)][Alias('NodeID','selector')][String[]]$ObjectID,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)][Alias('GroupID','asset_group_id')][Int[]]$NodeGroupID,
        [Parameter()][Switch]$Analyse,
        [Parameter()][Switch]$Force
        )
    Begin{NoMultiSession}
    Process{Foreach($NodeID in $ObjectID){if($Force -OR $(Confirm-Action "Remove Object $NodeID from Asset Group $NodegroupID")){
        # Get Selector
        $SelectSelect = Get-BHNodeGroup -ID $NodegroupID -Selector | ? selector -eq $NodeID
        # Remove Selector
        if($SelectSelect){$RemoveSelect=@{
            action = 'remove'
            selector_name = $SelectSelect.name
            sid = $SelectSelect.Selector
            } | ConvertTo-Json -Depth 11
        BHAPI api/v2/asset-groups/$NodeGroupID/selectors PUT "[$RemoveSelect]" -expand data.removed_selectors
        }}}}
    End{if($Analyze){Start-BHDataAnalysis -verbose:$false}}
    }
#End



## BloodHound Operator - BHPath
# Get-BHPath
# Get-BHPathFilter
# Select-BHPathFilter
# Get-BHPathQuery
# New-BHPathQuery
# Remove-BHPathQuery


################################################ Filter Enums

# BHPlatform
enum BHPlatform{
    AD
    AZ
    }
#End

# BHEdgeGroup
enum BHEdgeGroup{
    # AD
    ADStructure
    ADLateralMovement
    ADCredentialAccess
    ADObjectBasic
    ADObjectAdvanced
    ADCrossForest
    ADCertService
    ADNTLMRelay
    # AZ
    AZStructure
    AZADObjectBasic
    AZGraphRole
    AZCredentialAccess
    AZRMObjectBasic
    AZRMObjectAdvanced
    # X-Platform
    CrossPlatform
    }
#End

# BHEdge
enum BHEdge{
    ## AD
    # ADStructure
    #ClaimSpecialIdentity
    ContainsIdentity
    #DCFor
    GPOAppliesTo
    HasSIDHistory
    MemberOf
    PropagatesACEsTo
    SameForestTrust
    # ADLateralMovement
    AdminTo
    AllowedToAct
    AllowedToDelegate
    CanPSRemote
    CanRDP
    ExecuteDCOM
    SQLAdmin
    # ADCredentialAccess
    CoerceToTGT
    DCSync
    DumpSMSAPassword
    HasSession
    ReadGMSAPassword
    ReadLAPSPassword
    SyncLAPSPassword
    HasTrustKeys
    # ADObjectBasic
    AddMember
    AddSelf
    AllExtendedRights
    ForceChangePassword
    GenericAll
    Owns
    OwnsLimitedRights
    GenericWrite
    WriteDacl
    WriteOwner
    WriteOwnerLimitedRights
    # ADObjectAdvanced
    AddAllowedToAct
    AddKeyCredentialLink
    CanApplyGPO
    WriteAccountRestrictions
    WriteSPN
    WriteGPLink
    # ADCertService
    GoldenCert
    ADCSESC1
    ADCSESC3
    ADCSESC4
    ADCSESC6a
    ADCSESC6b
    ADCSESC9a
    ADCSESC9b
    ADCSESC10a
    ADCSESC10b
    ADCSESC13
    # ADCrossForest
    SpoofSIDHistory
    AbuseTGTDelegation
    # X-Platform
    SyncedToEntraUser
    # NTLMRelay
    CoerceAndRelayNTLMToSMB
    CoerceAndRelayNTLMToADCS
    CoerceAndRelayNTLMToLDAP
    CoerceAndRelayNTLMToLDAPS
    ## AZ
    # AZStructure
    AZAppAdmin
    AZCloudAppAdmin
    AZContains
    AZGlobalAdmin
    AZHasRole
    AZManagedIdentity
    AZMemberOf
    AZNodeResourceGroup
    AZPrivilegedAuthAdmin
    AZPrivilegedRoleAdmin
    AZRunsAs
    AZRoleEligible
    AZRoleApprover
    # AZADObjectBasic
    AZAddMembers
    AZAddOwner
    AZAddSecret
    AZExecuteCommand
    AZGrant
    AZGrantSelf
    AZOwns
    AZResetPassword
    # AZGraphRole
    AZMGAddMember
    AZMGAddOwner
    AZMGAddSecret
    AZMGGrantAppRoles
    AZMGGrantRole
    # AZCredentialAccess
    AZGetCertficates
    AZGetKeys
    AZGetSecrets
    # AZRMObjectBasic
    AZAvereContributor
    AZKeyVaultContributor
    AZOwner
    AZContributor
    AZUserAccessAdministrator
    AZVMAdminLogin
    AZVMContributor
    # AZRMObjectAdvanced
    AZAKSContributor
    AZAutomationContributor
    AZLogicAppContributor
    AZWebsiteContributor
    # X-Platform
    SyncedToADUser
    }
#End



################################################ Get-BHPathFilter

<#
.SYNOPSIS
    Get BloodHound Path Filter
.DESCRIPTION
    Get BloodHound Path Filter
.EXAMPLE
    BHFilter
#>
function Get-BHPathFilter{
    [CmdletBinding(DefaultParameterSetName='Selected')]
    [Alias('BHFilter')]
    Param(
        [Parameter(Mandatory=1,ParameterSetName='List')][Switch]$ListAll,
        [Parameter(Mandatory=0,ParameterSetName='Selected')][Switch]$String,
        [Parameter(Mandatory=0,ParameterSetName='Selected')][Switch]$Cypher
        )
    $EdgeList = @(
        ## AD
        # Structure
        #[PSCustomObject]@{Platform='AD'; Group='ADStructure'; Edge='ClaimSpecialIdentity'}
        [PSCustomObject]@{Platform='AD'; Group='ADStructure'; Edge='ContainsIdentity'}
        #[PSCustomObject]@{Platform='AD'; Group='ADStructure'; Edge='DCFor'}
        [PSCustomObject]@{Platform='AD'; Group='ADStructure'; Edge='GPOAppliesTo'}
        [PSCustomObject]@{Platform='AD'; Group='ADStructure'; Edge='HasSIDHistory'}
        [PSCustomObject]@{Platform='AD'; Group='ADStructure'; Edge='MemberOf'}
        [PSCustomObject]@{Platform='AD'; Group='ADStructure'; Edge='PropagatesACEsTo'}
        [PSCustomObject]@{Platform='AD'; Group='ADStructure'; Edge='SameForestTrust'}
        # Lateral Movement
        [PSCustomObject]@{Platform='AD'; Group='ADLateralMovement'; Edge='AdminTo'}
        [PSCustomObject]@{Platform='AD'; Group='ADLateralMovement'; Edge='AllowedToAct'}
        [PSCustomObject]@{Platform='AD'; Group='ADLateralMovement'; Edge='AllowedToDelegate'}
        [PSCustomObject]@{Platform='AD'; Group='ADLateralMovement'; Edge='CanPSRemote'}
        [PSCustomObject]@{Platform='AD'; Group='ADLateralMovement'; Edge='CanRDP'}
        [PSCustomObject]@{Platform='AD'; Group='ADLateralMovement'; Edge='ExecuteDCOM'}
        [PSCustomObject]@{Platform='AD'; Group='ADLateralMovement'; Edge='SQLAdmin'}
        # Credential Access
        [PSCustomObject]@{Platform='AD'; Group='ADCredentialAccess'; Edge='CoerceToTGT'}
        [PSCustomObject]@{Platform='AD'; Group='ADCredentialAccess'; Edge='DCSync'}
        [PSCustomObject]@{Platform='AD'; Group='ADCredentialAccess'; Edge='DumpSMSAPassword'}
        [PSCustomObject]@{Platform='AD'; Group='ADCredentialAccess'; Edge='HasSession'}
        [PSCustomObject]@{Platform='AD'; Group='ADCredentialAccess'; Edge='ReadGMSAPassword'}
        [PSCustomObject]@{Platform='AD'; Group='ADCredentialAccess'; Edge='ReadLAPSPassword'}
        [PSCustomObject]@{Platform='AD'; Group='ADCredentialAccess'; Edge='SyncLAPSPassword'}
        [PSCustomObject]@{Platform='AD'; Group='ADCredentialAccess'; Edge='HasTrustKeys'}
        # Obj Manipulation Basic
        [PSCustomObject]@{Platform='AD'; Group='ADObjectBasic'; Edge='AddMember'}
        [PSCustomObject]@{Platform='AD'; Group='ADObjectBasic'; Edge='AddSelf'}
        [PSCustomObject]@{Platform='AD'; Group='ADObjectBasic'; Edge='AllExtendedRights'}
        [PSCustomObject]@{Platform='AD'; Group='ADObjectBasic'; Edge='ForceChangePassword'}
        [PSCustomObject]@{Platform='AD'; Group='ADObjectBasic'; Edge='GenericAll'}
        [PSCustomObject]@{Platform='AD'; Group='ADObjectBasic'; Edge='Owns'}
        [PSCustomObject]@{Platform='AD'; Group='ADObjectBasic'; Edge='OwnsLimitedRights'}
        [PSCustomObject]@{Platform='AD'; Group='ADObjectBasic'; Edge='GenericWrite'}
        [PSCustomObject]@{Platform='AD'; Group='ADObjectBasic'; Edge='WriteDacl'}
        [PSCustomObject]@{Platform='AD'; Group='ADObjectBasic'; Edge='WriteOwner'}
        [PSCustomObject]@{Platform='AD'; Group='ADObjectBasic'; Edge='WriteOwnerLimitedRights'}
        # Obj Manipulation Advance
        [PSCustomObject]@{Platform='AD'; Group='ADObjectAdvanced'; Edge='AddAllowedToAct'}
        [PSCustomObject]@{Platform='AD'; Group='ADObjectAdvanced'; Edge='AddKeyCredentialLink'}
        [PSCustomObject]@{Platform='AD'; Group='ADObjectAdvanced'; Edge='CanApplyGPO'}
        [PSCustomObject]@{Platform='AD'; Group='ADObjectAdvanced'; Edge='WriteAccountRestrictions'}
        [PSCustomObject]@{Platform='AD'; Group='ADObjectAdvanced'; Edge='WriteSPN'}
        [PSCustomObject]@{Platform='AD'; Group='ADObjectAdvanced'; Edge='WriteGPLink'}
        # AD Cert Service
        [PSCustomObject]@{Platform='AD'; Group='ADCertService'; Edge='GoldenCert'}
        [PSCustomObject]@{Platform='AD'; Group='ADCertService'; Edge='ADCSESC1'}
        [PSCustomObject]@{Platform='AD'; Group='ADCertService'; Edge='ADCSESC3'}
        [PSCustomObject]@{Platform='AD'; Group='ADCertService'; Edge='ADCSESC4'}
        [PSCustomObject]@{Platform='AD'; Group='ADCertService'; Edge='ADCSESC6a'}
        [PSCustomObject]@{Platform='AD'; Group='ADCertService'; Edge='ADCSESC6b'}
        [PSCustomObject]@{Platform='AD'; Group='ADCertService'; Edge='ADCSESC9a'}
        [PSCustomObject]@{Platform='AD'; Group='ADCertService'; Edge='ADCSESC9b'}
        [PSCustomObject]@{Platform='AD'; Group='ADCertService'; Edge='ADCSESC10a'}
        [PSCustomObject]@{Platform='AD'; Group='ADCertService'; Edge='ADCSESC10b'}
        [PSCustomObject]@{Platform='AD'; Group='ADCertService'; Edge='ADCSESC13'}
        # Cross Forest Trust Abuse
        [PSCustomObject]@{Platform='AD'; Group='ADCrossForest'; Edge='SpoofSIDHistory'}
        [PSCustomObject]@{Platform='AD'; Group='ADCrossForest'; Edge='AbuseTGTDelegation'}
        # X-Platform
        [PSCustomObject]@{Platform='AD'; Group='CrossPlatform'; Edge='SyncedToEntraUser'}
        # NTLM Relay
        [PSCustomObject]@{Platform='AD'; Group='ADNTLMRelay'; Edge='CoerceAndRelayNTLMToSMB'}
        [PSCustomObject]@{Platform='AD'; Group='ADNTLMRelay'; Edge='CoerceAndRelayNTLMToADCS'}
        [PSCustomObject]@{Platform='AD'; Group='ADNTLMRelay'; Edge='CoerceAndRelayNTLMToLDAP'}
        [PSCustomObject]@{Platform='AD'; Group='ADNTLMRelay'; Edge='CoerceAndRelayNTLMToLDAPS'}
        ## AZ
        # Structure
        [PSCustomObject]@{Platform='AZ'; Group='AZStructure'; Edge='AZAppAdmin'}
        [PSCustomObject]@{Platform='AZ'; Group='AZStructure'; Edge='AZCloudAppAdmin'}
        [PSCustomObject]@{Platform='AZ'; Group='AZStructure'; Edge='AZContains'}
        [PSCustomObject]@{Platform='AZ'; Group='AZStructure'; Edge='AZGlobalAdmin'}
        [PSCustomObject]@{Platform='AZ'; Group='AZStructure'; Edge='AZHasRole'}
        [PSCustomObject]@{Platform='AZ'; Group='AZStructure'; Edge='AZManagedIdentity'}
        [PSCustomObject]@{Platform='AZ'; Group='AZStructure'; Edge='AZMemberOf'}
        [PSCustomObject]@{Platform='AZ'; Group='AZStructure'; Edge='AZNodeResourceGroup'}
        [PSCustomObject]@{Platform='AZ'; Group='AZStructure'; Edge='AZPrivilegedAuthAdmin'}
        [PSCustomObject]@{Platform='AZ'; Group='AZStructure'; Edge='AZPrivilegedRoleAdmin'}
        [PSCustomObject]@{Platform='AZ'; Group='AZStructure'; Edge='AZRunsAs'}
        [PSCustomObject]@{Platform='AZ'; Group='AZStructure'; Edge='AZRoleEligible'}
        [PSCustomObject]@{Platform='AZ'; Group='AZStructure'; Edge='AZRoleApprover'}
        # AAD Obj Manipulation
        [PSCustomObject]@{Platform='AZ'; Group='AZADObjectBasic'; Edge='AZAddMembers'}
        [PSCustomObject]@{Platform='AZ'; Group='AZADObjectBasic'; Edge='AZAddOwner'}
        [PSCustomObject]@{Platform='AZ'; Group='AZADObjectBasic'; Edge='AZAddSecret'}
        [PSCustomObject]@{Platform='AZ'; Group='AZADObjectBasic'; Edge='AZExecuteCommand'}
        [PSCustomObject]@{Platform='AZ'; Group='AZADObjectBasic'; Edge='AZGrant'}
        [PSCustomObject]@{Platform='AZ'; Group='AZADObjectBasic'; Edge='AZGrantSelf'}
        [PSCustomObject]@{Platform='AZ'; Group='AZADObjectBasic'; Edge='AZOwns'}
        [PSCustomObject]@{Platform='AZ'; Group='AZADObjectBasic'; Edge='AZResetPassword'}
        # MSGraph Role Abuse
        [PSCustomObject]@{Platform='AZ'; Group='AZGraphRole'; Edge='AZMGAddMember'}
        [PSCustomObject]@{Platform='AZ'; Group='AZGraphRole'; Edge='AZMGAddOwner'}
        [PSCustomObject]@{Platform='AZ'; Group='AZGraphRole'; Edge='AZMGAddSecret'}
        [PSCustomObject]@{Platform='AZ'; Group='AZGraphRole'; Edge='AZMGGrantAppRoles'}
        [PSCustomObject]@{Platform='AZ'; Group='AZGraphRole'; Edge='AZMGGrantRole'}
        # Credential Access
        [PSCustomObject]@{Platform='AZ'; Group='AZCredentialAccess'; Edge='AZGetCertificates'}
        [PSCustomObject]@{Platform='AZ'; Group='AZCredentialAccess'; Edge='AZGetKeys'}
        [PSCustomObject]@{Platform='AZ'; Group='AZCredentialAccess'; Edge='AZGetSecrets'}
        # AzRM Object Manipulation Basic
        [PSCustomObject]@{Platform='AZ'; Group='AZRMObjectBasic'; Edge='AZAvereContributor'}
        [PSCustomObject]@{Platform='AZ'; Group='AZRMObjectBasic'; Edge='AZKeyVaultContributor'}
        [PSCustomObject]@{Platform='AZ'; Group='AZRMObjectBasic'; Edge='AZOwner'}
        [PSCustomObject]@{Platform='AZ'; Group='AZRMObjectBasic'; Edge='AZContributor'}
        [PSCustomObject]@{Platform='AZ'; Group='AZRMObjectBasic'; Edge='AZUserAccessAdministrator'}
        [PSCustomObject]@{Platform='AZ'; Group='AZRMObjectBasic'; Edge='AZVMAdminLogin'}
        [PSCustomObject]@{Platform='AZ'; Group='AZRMObjectBasic'; Edge='AZVMContributor'}
        # AzRM Object Manipulation Adavnced
        [PSCustomObject]@{Platform='AZ'; Group='AZRMObjectAdvanced'; Edge='AZAKSContributor'}
        [PSCustomObject]@{Platform='AZ'; Group='AZRMObjectAdvanced'; Edge='AZAutomationContributor'}
        [PSCustomObject]@{Platform='AZ'; Group='AZRMObjectAdvanced'; Edge='AZLogicAppContributor'}
        [PSCustomObject]@{Platform='AZ'; Group='AZRMObjectAdvanced'; Edge='AZWebsiteContributor'}
        # X-Platform
        [PSCustomObject]@{Platform='AZ'; Group='CrossPlatform'; Edge='SyncedToADUser'}
        )
    # List All
    if($ListAll){if($BHFilter){$BHFilter}else{$EdgeList}}
    # Selected
    else{$SelectedEdge = $BHFilter | ? x
        if($Cypher){
            $Str=':'+(($SelectedEdge.Edge|Sort-Object)-join'|')
            if(($BHSession|? x).CypherClip){try{$Str|Set-Clipboard}Catch{}}
            $str
            }
        #elseif($String){($SelectedEdge.Edge|Sort-Object)-join','}
        elseif($String){"'"+(($SelectedEdge.Edge|Sort-Object)-join"','")+"'"}
        else{$SelectedEdge}
        }}
#####End



################################################ Select-BHPathFilter

<#
.SYNOPSIS
    Select BloodHound Path Filter
.DESCRIPTION
    Select BloodHound Path Filter
.EXAMPLE
    Select-BHFilter
#>
function Select-BHPathFilter{
    [Alias('BHFilterSelect')]
    Param(
        [Parameter(Mandatory=1,ParameterSetName='All')][Switch]$All,
        [Parameter(Mandatory=1,ParameterSetName='None')][Switch]$None,
        [Parameter(Mandatory=1,ParameterSetName='Platform')][BHPlatform[]]$Platform,
        [Parameter(Mandatory=1,ParameterSetName='EdgeGroup')][Alias('Group')][BHEdgeGroup[]]$EdgeGroup,
        [Parameter(Mandatory=1,ParameterSetName='Edge')][BHEdge[]]$Edge,
        [Parameter(Mandatory=0,ParameterSetName='Platform')]
        [Parameter(Mandatory=0,ParameterSetName='EdgeGroup')]
        [Parameter(Mandatory=0,ParameterSetName='Edge')][Switch]$NoSelect
        )
    $xVal = if($NoSelect){$Null}else{'x'}
    Switch($PSCmdlet.ParameterSetName){
        # All
        All {$Script:BHFilter = Get-BHPathFilter -List | Select Platform,Group,@{n='x';e={'x'}},Edge}
        # None
        None{$Script:BHFilter|? x |%{$_.x=$Null}}
        # Platform
        Platform{foreach($Plt in $Platform){$Script:BHFilter|? Platform -eq $Plt |%{$_.x=$xVal}}}
        # EdgeGroup
        EdgeGroup{foreach($Grp in $EdgeGroup){$Script:BHFilter|? Group -eq $Grp |%{$_.x=$xVal}}}
        # Edge
        Edge{foreach($Edg in $Edge){$Script:BHFilter|? Edge -eq $Edg |%{$_.x=$xVal}}}
        }}
#####End



################################################ Get-BHPath

<#
.SYNOPSIS
    Get BloodHound Path
.DESCRIPTION
    Get BloodHound Path
.EXAMPLE
    BHPath
#>
function Get-BHPath{
    [CmdletBinding(DefaultParameterSetName='Query')]
    [Alias('Invoke-BHCypher','BHCypher')]
    Param(
        [Parameter(Mandatory=1,Position=0,ParameterSetName='Query',ValueFromPipeline)][Alias('q')][String]$Query,
        [Parameter(Mandatory=0,ParameterSetName='Manual')]
        [Parameter(Mandatory=0,ParameterSetName='ByID')][Alias('Any')][Switch]$All,
        [Parameter(Mandatory=0,ParameterSetName='Manual')]
        [Parameter(Mandatory=0,ParameterSetName='ByID')][Switch]$Shortest,
        [Parameter(Mandatory=0,ParameterSetName='Manual')][alias('x')][String]$Source,
        [Parameter(Mandatory=0,ParameterSetName='Manual')][alias('y')][String]$Target,
        [Parameter(Mandatory=0,ParameterSetName='ByID')][alias('xID')][String[]]$SourceID,
        [Parameter(Mandatory=1,ParameterSetName='ByID')][AllowNull()][alias('yID')][String[]]$TargetID,
        [Parameter(Mandatory=0,ParameterSetName='Manual')]
        [Parameter(Mandatory=0,ParameterSetName='ByID')][alias('r','e')][String[]]$Edge=':{}',
        [Parameter(Mandatory=0,ParameterSetName='Manual')]
        [Parameter(Mandatory=0,ParameterSetName='ByID')][alias('n')][String]$Hop='1..',
        [Parameter(Mandatory=0,ParameterSetName='Manual')]
        [Parameter(Mandatory=0,ParameterSetName='ByID')][alias('xWhere','x?')][String]$SourceWhere,
        [Parameter(Mandatory=0,ParameterSetName='Manual')]
        [Parameter(Mandatory=0,ParameterSetName='ByID')][alias('yWhere','y?')][String]$TargetWhere,
        [Parameter(Mandatory=0,ParameterSetName='Manual')]
        [Parameter(Mandatory=0,ParameterSetName='ByID')][alias('pWhere','p?')][String]$PathWhere,
        [ValidateSet('p','x','y')]
        [Parameter(Mandatory=0,ParameterSetName='Manual')]
        [Parameter(Mandatory=0,ParameterSetName='ByID')][String]$Return='p',
        [Parameter(Mandatory=0,ParameterSetName='Manual')]
        [Parameter(Mandatory=0,ParameterSetName='ByID')][String]$OrderBy,
        [Parameter(Mandatory=0,ParameterSetName='Manual')]
        [Parameter(Mandatory=0,ParameterSetName='ByID')][Int]$Limit=$($BHSession|? x|select -last 1).limit,
        [Parameter(Mandatory=0)][Switch]$Cypher,
        [Parameter(Mandatory=0)][Switch]$NoConvert,
        [Parameter(Mandatory=0)][Switch]$Minimal,
        [Parameter(Mandatory=0)][Alias('dot')][String]$Expand,
        [Parameter(Mandatory=0)][Alias('Prefer')][int]$Timeout
)
    Process{
    # Source / Target
    if($Source -AND $Source -notmatch "^\{"){if($Source -notmatch "^\:"){$Source=":$Source"}}
    if($Target -AND $Target -notmatch "^\{"){if($Target -notmatch "^\:"){$Target=":$Target"}}
    if($SourceID){$SourceWHere = "x.objectid IN ['$($SourceID-join"','")']"}
    if($TargetID){$TargetWHere = "y.objectid IN ['$($TargetID-join"','")']"}
    # Path Type
    $pType = if($All -AND $Shortest){'allShortestPaths'}
         elseif($Shortest -AND -Not$All){'shortestPath'}
         elseif($All -AND -Not$Shortest){}
         else{'shortestPath'}
    # Hop
    $Hop = if($All -AND -Not$Shortest){if($Hop){$Hop}}else{
        if($Hop){if($Hop -notmatch "\.\."){"1..$Hop"}else{$Hop}}else{$Null}
        }
    # EdgeFilter
    $EFilter = if($Edge -eq ':{}'){$((Get-BHPathFilter -Cypher).trim(':'))}else{$Edge-Join'|'}
    if($Edge.count -AND $Efilter -notmatch "^\:"){$EFilter=":$Efilter"}
    if($Source -eq $target -OR -Not$Source -OR -Not$Target){$PathWhere=(("($PathWhere)","x<>y")-ne'()')-join' AND '}
    # Query
    $CypherQ = if($Query){$Query}else{
"$(if($Source -OR $SourceWhere){"MATCH (x$Source)$(if($SourceWhere){" WHERE $SourceWhere"})"})$(
if($Target -OR $TargetWhere){"`r`nMATCH (y$Target)$(if($TargetWhere){" WHERE $TargetWhere"})"})
$(If($Optional){'OPTIONAL '})MATCH p=$pType((x)-[r$EFilter$(if($Hop){"*$Hop"})]->(y))$(if($PathWhere){"`r`nWHERE $PathWhere"})
RETURN $Return$(if($OrderBy){"`r`nORDER BY $OrderBy"})$(if($Limit){"`r`nLIMIT $Limit"})"
        }
    $CypherQ = $CypherQ.replace("-[:{}","-[$(Get-BHPathFilter -Cypher)").replace("-[:*","-[*")
    $CypherQ = $CypherQ.replace("-[r:{",'-[r{').replace("-[r:*",'-[r*').replace("-[r:]",'-[r]')
    ## Cypher
    if($Cypher){if(($BHSession|? x|Select -last 1).CypherClip){$CypherQ.trim()|Set-Clipboard};RETURN $CypherQ.trim()}
    # API Call
    Write-Verbose "[BH] POST api/v2/graphs/cypher
$($CypherQ.trim())"
    $Body = @{query=$CypherQ;include_properties=$(-Not$Minimal)}|ConvertTo-Json
    $QData = Invoke-BHAPI 'api/v2/graphs/cypher' -Method POST -Body $Body -expand $(if($NoConvert){$Expand}else{'data'}) -verbose:$False -Timeout:$Timeout
    #$QData = BHPath -Query $CypherQ.trim() -Verbose:$false
    #if(-Not$shortest -AND -Not$All){$QData.edges=$QData.Edges|Sort-Object {"$($_.sourceS)-$($_.Target)"} -unique}
    ## NoConvert
    if($NoConvert){$QData | Select-Object -expand $Expand; RETURN}
    # Convert
    if($QData.edges.count){
        $PathID=0;$StepID=0
        For($Index=0;$Index -lt $QData.edges.count;$Index++){
            $Rel = $QData.Edges[$Index]
            $Src = $QData.nodes.$($Rel.Source)
            $tgt = $QData.nodes.$($Rel.target)
            # Edge Obj
            [PSCustomObject]@{
                ID                = $PathID
                Step              = $StepID
                SourceType        = $Src.Kind
                Source            = $Src.label
                Edge              = $Rel.label
                TargetType        = $tgt.Kind
                Target            = $tgt.label
                IsTierZeroSource  = $Src.IsTierZero
                IsTierZeroTarget  = $Tgt.IsTierZero
                TierZeroViolation = $Tgt.IsTierZero -AND -Not$Src.IsTierZero #-AND $Rel.Label -notin ('Contains','LocalToComputer','GetChanges')
                SourceID          = $Src.objectID
                TargetID          = $Tgt.objectID
                #LastSeen          = $Rel.lastseen
                EdgeProps         = $Rel.Properties
                }
            # Next IDs
            if($Rel.Target -eq $QData.Edges[$Index+1].source){$StepID+=1}
            else{$PathID+=1;$StepID=0}
            }}
    # Return x|y
    elseif($QData.nodes -AND ($QData.nodes|GM|? MemberType -eq noteproperty).name){
        $Out = ($QData.nodes|GM|? MemberType -eq noteproperty).name| %{$QData.nodes."$_"}
        if($Expand){foreach($Dot in $Expand.split('.')){$Out=try{$Out.$Dot}Catch{$Out}}}
        RETURN $Out
        }
    }}
#End



####################################################### BHPathComposition


<#
.SYNOPSIS
    Get BloodHound Path Composition
.DESCRIPTION
    Get BloodHound Path Composition
.EXAMPLE
    Get-BHPathComposition -SourceID $x -EdgeType $r -TargetID $y
.EXAMPLE
    BHPath "MATCH p=(:User{name:'$UserName'})-[:ADCSESC1]->(:Domain) RETURN p" | BHComposition | ft
#>
function Get-BHPathComposition{
    [Alias('BHComposition')]
    Param(
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)][string]$SourceID,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)][string]$TargetID,
        #[ValidateSet('ADCSESC1')] <------------------------------------------------------------- ToDo: Add valid edge set
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)][Alias('Edge')][String]$EdgeType
        #[Parameter()][Switch]$Cypher <---------------------------------------------------------- ToDo: list of Composition queries
        )
    Begin{$idx=0;$stp=0}
    Process{
        if($Sourceid -notmatch "^\d+$"){$Sourceid = try{((BHCypher "MATCH (x{objectid:'$SourceID'}) RETURN x" -NoConvert -verbose:$False).data.nodes|gm|? Membertype -eq Noteproperty).name}Catch{}}
        if($Targetid -notmatch "^\d+$"){$Targetid = try{((BHCypher "MATCH (x{objectid:'$TargetID'}) RETURN x" -NoConvert -verbose:$False).data.nodes|gm|? Membertype -eq Noteproperty).name}catch{}}
        if(-Not$SourceID -OR -Not$TargetID){Break}
        $qfilter = @(
            "source_node=$SourceID",
            "target_node=$TargetID",
            "edge_type=$EdgeType"
            )
        #$RelayEdges = 'CoerceAndRelayNTLMToSMB','CoerceAndRelayNTLMToLDAP','CoerceAndRelayNTLMToLDAPS','CoerceAndRelayNTLMToADCS'
        $CallURL=if($EdgeType -IN $RelayEdges){'api/v2/graphs/relay-targets'}else{'api/v2/graphs/edge-composition'}
        $CompData = BHAPI $CallURL -Filter $qFilter -dot data
        for($i=0;$i -lt $CompData.edges.count;$i++){
            $CurrentEdge = $CompData.edges[$i]
            $SrcNode     = $CompData.Nodes.$($CurrentEdge.source)
            $TgtNode     = $CompData.Nodes.$($CurrentEdge.target)
            $CurrentEdge | Add-Member -MemberType NoteProperty -Name source_node -Value $SrcNode -Force
            $CurrentEdge | Add-Member -MemberType NoteProperty -Name target_node -Value $TgtNode -Force
            [PSCustomObject]@{
                ID         = $idx
                Step       = $stp
                SourceType = $CurrentEdge.source_node.kind
                Source     = $CurrentEdge.source_node.label
                Edge       = $CurrentEdge.Kind
                TargetType = $CurrentEdge.target_node.kind
                Target     = $CurrentEdge.target_node.label
                IsTierZeroSource = $CurrentEdge.source_node.isTierZero
                IsTierZeroTarget = $CurrentEdge.target_node.isTierZero
                TierZeroViolation = $CurrentEdge.target_node.IsTierZero -AND -Not$CurrentEdge.source_node.IsTierZero
                SourceId  = $CurrentEdge.source_node.objectid
                TargetId  = $CurrentEdge.target_node.objectid
                EdgeProps = $CurrentEdge.Properties
                }
            if($CurrentEdge.Target -eq $CompData.edges[$i+1].source){$stp+=1}else{$idx+=1;$Stp=0}
            }
        }
    End{}
    }
#End



<#
.SYNOPSIS
    Get BloodHound Relay Target
.DESCRIPTION
    Get BloodHound Relay Target
.EXAMPLE
    Get-BHPathRelayTarget -SourceID $x -EdgeType $r -TargetID $y
#>
function Get-BHPathRelayTarget{
    [Alias('BHRelayTarget')]
    Param(
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)][string]$SourceID,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)][string]$TargetID,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)][Alias('Edge')][String]$EdgeType
        )
    Begin{$idx=0;$stp=0}
    Process{
        if($Sourceid -notmatch "^\d+$"){$Sourceid = try{((BHCypher "MATCH (x{objectid:'$SourceID'}) RETURN x" -NoConvert -verbose:$False).data.nodes|gm|? Membertype -eq Noteproperty).name}Catch{}}
        if($Targetid -notmatch "^\d+$"){$Targetid = try{((BHCypher "MATCH (x{objectid:'$TargetID'}) RETURN x" -NoConvert -verbose:$False).data.nodes|gm|? Membertype -eq Noteproperty).name}catch{}}
        if(-Not$SourceID -OR -Not$TargetID){Break}
        $qfilter = @(
            "source_node=$SourceID",
            "target_node=$TargetID",
            "edge_type=$EdgeType"
            )
        #$RelayEdges = 'CoerceAndRelayNTLMToSMB','CoerceAndRelayNTLMToLDAP','CoerceAndRelayNTLMToLDAPS','CoerceAndRelayNTLMToADCS'
        $CallURL=if($EdgeType -IN $RelayEdges){'api/v2/graphs/relay-targets'}else{'api/v2/graphs/relay-targets'}
        $CompData = BHAPI $CallURL -Filter $qFilter -dot data
        for($i=0;$i -lt $CompData.edges.count;$i++){
            $CurrentEdge = $CompData.edges[$i]
            $SrcNode     = $CompData.Nodes.$($CurrentEdge.source)
            $TgtNode     = $CompData.Nodes.$($CurrentEdge.target)
            $CurrentEdge | Add-Member -MemberType NoteProperty -Name source_node -Value $SrcNode -Force
            $CurrentEdge | Add-Member -MemberType NoteProperty -Name target_node -Value $TgtNode -Force
            [PSCustomObject]@{
                ID         = $idx
                Step       = $stp
                SourceType = $CurrentEdge.source_node.kind
                Source     = $CurrentEdge.source_node.label
                Edge       = $CurrentEdge.Kind
                TargetType = $CurrentEdge.target_node.kind
                Target     = $CurrentEdge.target_node.label
                IsTierZeroSource = $CurrentEdge.source_node.isTierZero
                IsTierZeroTarget = $CurrentEdge.target_node.isTierZero
                TierZeroViolation = $CurrentEdge.target_node.IsTierZero -AND -Not$CurrentEdge.source_node.IsTierZero
                SourceId  = $CurrentEdge.source_node.objectid
                TargetId  = $CurrentEdge.target_node.objectid
                EdgeProps = $CurrentEdge.Properties
                }
            if($CurrentEdge.Target -eq $CompData.edges[$i+1].source){$stp+=1}else{$idx+=1;$Stp=0}
            }
        }
    End{}
    }
#End


<#
.SYNOPSIS
    Get BloodHound ACL Inheritance
.DESCRIPTION
    Get BloodHound ACL Inheritance
.EXAMPLE
    Get-BHPathACLInheritance -SourceID $x -EdgeType $r -TargetID $y
#>
function Get-BHPathACLInheritance{
    [Alias('BHACLInheritance')]
    Param(
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)][string]$SourceID,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)][string]$TargetID,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)][Alias('Edge')][String]$EdgeType
        )
    Begin{$idx=0;$stp=0}
    Process{
        if($Sourceid -notmatch "^\d+$"){$Sourceid = try{((BHCypher "MATCH (x{objectid:'$SourceID'}) RETURN x" -NoConvert -verbose:$False).data.nodes|gm|? Membertype -eq Noteproperty).name}Catch{}}
        if($Targetid -notmatch "^\d+$"){$Targetid = try{((BHCypher "MATCH (x{objectid:'$TargetID'}) RETURN x" -NoConvert -verbose:$False).data.nodes|gm|? Membertype -eq Noteproperty).name}catch{}}
        if(-Not$SourceID -OR -Not$TargetID){Break}
        $qfilter = @(
            "source_node=$SourceID",
            "target_node=$TargetID",
            "edge_type=$EdgeType"
            )
        #$RelayEdges = 'CoerceAndRelayNTLMToSMB','CoerceAndRelayNTLMToLDAP','CoerceAndRelayNTLMToLDAPS','CoerceAndRelayNTLMToADCS'
        $CallURL=if($EdgeType -IN $RelayEdges){'api/v2/graphs/relay-targets'}else{'api/v2/graphs/acl-inheritance'}
        $CompData = BHAPI $CallURL -Filter $qFilter -dot data
        RETURN $CompData
        for($i=0;$i -lt $CompData.edges.count;$i++){
            $CurrentEdge = $CompData.edges[$i]
            $SrcNode     = $CompData.Nodes.$($CurrentEdge.source)
            $TgtNode     = $CompData.Nodes.$($CurrentEdge.target)
            $CurrentEdge | Add-Member -MemberType NoteProperty -Name source_node -Value $SrcNode -Force
            $CurrentEdge | Add-Member -MemberType NoteProperty -Name target_node -Value $TgtNode -Force
            [PSCustomObject]@{
                ID         = $idx
                Step       = $stp
                SourceType = $CurrentEdge.source_node.kind
                Source     = $CurrentEdge.source_node.label
                Edge       = $CurrentEdge.Kind
                TargetType = $CurrentEdge.target_node.kind
                Target     = $CurrentEdge.target_node.label
                IsTierZeroSource = $CurrentEdge.source_node.isTierZero
                IsTierZeroTarget = $CurrentEdge.target_node.isTierZero
                TierZeroViolation = $CurrentEdge.target_node.IsTierZero -AND -Not$CurrentEdge.source_node.IsTierZero
                SourceId  = $CurrentEdge.source_node.objectid
                TargetId  = $CurrentEdge.target_node.objectid
                EdgeProps = $CurrentEdge.Properties
                }
            if($CurrentEdge.Target -eq $CompData.edges[$i+1].source){$stp+=1}else{$idx+=1;$Stp=0}
            }
        }
    End{}
    }
#End

############################################################# Saved Queries

<#
.SYNOPSIS
    Get BloodHound Query
.DESCRIPTION
    Get BloodHound Saved Query 
.EXAMPLE
    BHQuery
.EXAMPLE
    BHQuery -ID 123
.EXAMPLE
    BHQuery -name MyQuery
.EXAMPLE
    BHQuery -description <keyword>
.EXAMPLE
    BHQuery -scope <shared|public>
#>
function Get-BHPathQuery{
    [CmdletBinding(DefaultParameterSetName='ByID')]
    [Alias('BHQuery','Get-BHQuery')]
    Param(
        [Parameter(Mandatory=0,Position=0,ParameterSetName='ByID')][String[]]$ID,
        [Parameter(Mandatory=1,ParameterSetName='ByName')][String[]]$Name,
        [ValidateSet('public','shared')]
        [Parameter(Mandatory=1,ParameterSetName='ByScope')][String]$Scope,
        [Parameter(Mandatory=1,ParameterSetName='ByDescription')][String[]]$Description,
        #[Parameter(Mandatory=1,ParameterSetName='FromRepo')][Alias('FromMartin')][Switch]$OnlineLibrary,
        [Parameter(Mandatory=0)][String]$Expand='data',
        [Parameter(Mandatory=0)][SWitch]$Cypher
        )
    NoMultiSession
    $Out = Switch($PSCmdlet.ParameterSetName){
        ByID{$Q=BHAPI api/v2/saved-queries -expand $Expand
            if($ID){$Q|Where id -In $ID}else{$Q}
            }
        ByName{BHAPI api/v2/saved-queries -Filter "name=~eq:$Name" -expand $Expand}
        ByDescription{BHAPI api/v2/saved-queries -Filter "description=~eq:$Description" -expand $expand}
        ByScope{BHAPI api/v2/saved-queries -Filter "scope=$Scope" -expand $expand}
        }
    if($Cypher -AND -Not$OnlineLibray){if(($BHSession|? x|Select -last 1).CypherClip){$Out.Query.trim()|Set-Clipboard};RETURN $Out.Query.trim()}
    else{$Out}
    }
#End

<#
.SYNOPSIS
    New BloodHound Query
.DESCRIPTION
    New BloodHound saved query 
.EXAMPLE
    New-BHPathQuery -Name MySavedQuery -Query "MATCH (x:User) RETURN x LIMIT 1" -Desc "My Saved Query"
#>
function New-BHPathQuery{
    [Alias('New-BHQuery')]
    Param(
        [Parameter(Mandatory=1,ValueFromPipelineByPropertyName)][String]$Name,
        #[ValidateSet('AD','AZ')]
        #[Parameter(Mandatory=0,ValueFromPipelineByPropertyName)][String]$Platform,
        #[Parameter(Mandatory=0,ValueFromPipelineByPropertyName)][String]$Category,
        [Parameter(Mandatory=0,ValueFromPipelineByPropertyName)][String]$Description='Custom Query',
        [Parameter(Mandatory=1,ValueFromPipelineByPropertyName)][String]$Query,
        [Parameter(Mandatory=0)][Switch]$PassThru
        )
    Begin{NoMultiSession}
    Process{
        # Body
        $Body = @{
            name  = $Name
            description = $Description
            query = $Query.trim()
            }
        #if($Platform){$Body['Platform']=$Platform}
        #if($Category){$Body['Category']=$Category}
        if($Description){$Body['Description']=$Description}
        $SQ = Invoke-BHAPI api/v2/saved-queries -Method POST -Body ($Body| ConvertTo-Json) -expand data
        if($PassThru){$SQ}
        }
    End{}
    }
#End

<#
.SYNOPSIS
    Set BloodHound Query
.DESCRIPTION
    Set BloodHound saved query 
.EXAMPLE
    Set-BHPathQuery -ID 123 -Name MySavedQuery
#>
function Set-BHPathQuery{
    [Alias('Set-BHQuery')]
    Param(
        [Parameter(Mandatory=1)][int]$ID,
        [Parameter(Mandatory=0)][String]$Name,
        [Parameter(Mandatory=0)][String]$Query,
        [Parameter(Mandatory=0)][String]$Description
        )
    NoMultiSession
    $QObj = Get-BHPathQuery -id $ID | Select Name,Description,Query
    if($QObj){
        if($Name){$QObj.Name=$Name}
        if($Query){$QObj.Query=$Query}
        if($Description){$QObj.Description=$Description}
        BHAPI saved-queries/$ID PUT ($QObj|Convertto-Json) -Expand data
        }
    }
#End

<#
.SYNOPSIS
    Set BloodHound Query Scope
.DESCRIPTION
    Set BloodHound saved query sharing scope
.EXAMPLE
    Set-BHQueryScope -ID 123 -Public
.EXAMPLE
    Set-BHQueryScope -ID 123 -Private
.EXAMPLE
    Set-BHQueryScope -ID 123 -Share <UserID[]>
.EXAMPLE
    Set-BHQueryScope -ID 123 -Share <UserID[]> -Remove
#>
function Set-BHPathQueryScope{
    [Alias('Set-BHQueryScope')]
    Param(
        [Parameter(Mandatory=1,Position=0)][int]$ID,
        [Parameter(Mandatory=1,ParameterSetName='Public')][Switch]$Public,
        [Parameter(Mandatory=1,ParameterSetName='Private')][Switch]$Private,
        [Parameter(Mandatory=1,ParameterSetName='Share')][String[]]$Share,
        [Parameter(Mandatory=0,ParameterSetName='Share')][Switch]$Remove
        )
    NoMultiSession
    $Perm=Switch($PSCmdlet.ParameterSetName){
        Private{@{public=$false}}
        Public {@{public=$true}}
        Share  {@{user_ids=@($Share);public=$false}}
        }
    $Verb=if($Remove){'DELETE'}Else{'PUT'}
    BHAPI saved-queries/$ID/permissions $Verb -Body ($Perm|Convertto-Json)
    }
#End


<#
.SYNOPSIS
    Remove BloodHound Saved Query
.DESCRIPTION
    Remove BloodHound saved query
.EXAMPLE
    Remove-BHPathQuery -id <QueryID> -Force
#>
Function Remove-BHPathQuery{
    [Alias('Remove-BHQuery')]
    Param(
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)][String]$ID,
        [Parameter()][Switch]$Force
        )
    Begin{NoMultiSession}
    Process{foreach($Qid in $ID){if($Force -OR (Confirm-Action "Delete saved query ID $Qid")){
        Invoke-BHAPI api/v2/saved-queries/$Qid -Method DELETE | out-Null
        Start-Sleep -Milliseconds 10
        }}}
    End{}
    }
#End

<#
.SYNOPSIS
    Invoke BloodHound Query
.DESCRIPTION
    Invoke BloodHound query
.EXAMPLE
    Invoke-BHQuery "MATCH (x:User) RETURN x LIMIT 1"
.EXAMPLE
    Invoke-BHQuery "api/version"
.EXAMPLE
    BHQuery -ID 123 | BHInvoke
.EXAMPLE
    "MATCH (x{objectid:'${oid}'}) RETURN x" | BHInvoke -Param @{oid='S-1-5-21-928081958-2569533466-1777930793-1800'}
#>
Function Invoke-BHPathQuery{
    [Alias('BHInvoke','Invoke-BHQuery')]
    Param(
        [Parameter(Mandatory=1,ValueFromPipeline,ValueFromPipelineByPropertyName)][String]$Query,
        [Parameter(Mandatory=0,ValueFromPipelineByPropertyName)][String]$Description,
        [Parameter(Mandatory=0,ValueFromPipelineByPropertyName)][String]$Name,
        [Parameter(Mandatory=0,ValueFromPipelineByPropertyName)][Alias('GUID')][String]$ID,
        [Parameter(Mandatory=0,ValueFromPipelineByPropertyName)][ALias('Platforms')][String[]]$Platform,
        [Parameter(Mandatory=0,ValueFromPipelineByPropertyName)][String]$Category,
        [Parameter(Mandatory=0)][Hashtable]$Param,
        [Parameter(Mandatory=0)][Switch]$Minimal,
        [Parameter(Mandatory=0)][String]$Expand,
        [Parameter(Mandatory=0)][String[]]$Select,
        [Parameter(Mandatory=0)][Switch]$Cypher
        )
    Begin{}
    Process{Foreach($CQ in $Query){
        if($Param){Foreach($Key in $Param.keys){$CQ=$CQ.replace("`${$Key}",$Param.$Key)}}
        $QStart = [Datetime]::utcnow
        $QRes   = if($CQ -match "\/?api\/"){BHAPI $CQ -expand Data}else{
            BHCypher $CQ -Minimal:$Minimal -Cypher:$Cypher
            if($Cypher){RETURN $QRes}
            }
        $QStop  = [Datetime]::utcnow
        if($Expand){foreach($Field in ($Expand.split('.')-ne'Result')){
            $QRes=$QRes.$field
            }}
        if($Select){$QRes = $QRes | Select-Object $Select}
        $Obj = [PSCustomObject]@{}
        if($ID){$Obj|Add-Member -MemberType NoteProperty -Name ID -Value $ID}
        if($Platform){$Obj|Add-Member -MemberType NoteProperty -Name Platform -Value $Platform}
        if($Category){$Obj|Add-Member -MemberType NoteProperty -Name Category -Value $Category}
        if($Name){$Obj|Add-Member -MemberType NoteProperty -Name Name -Value $Name}
        if($Description){$Obj|Add-Member -MemberType NoteProperty -Name Description -Value $Description}
        $Obj|Add-Member -MemberType NoteProperty -Name Query -Value $CQ.trim()
        $Obj|Add-Member -MemberType NoteProperty -Name Result -Value $QRes
        $Obj|Add-Member -MemberType NoteProperty -Name Count -Value $(if($Qres.SourceType -AND $QRes.Step){$Qres[-1].id+1}else{$QRes.Count})
        $Obj|Add-Member -MemberType NoteProperty -Name Timestamp -Value $QStart
        $Obj|Add-Member -MemberType NoteProperty -Name Duration -Value $($QStop-$QStart)
        if("result" -in ($Expand.split('.'))){$Obj|Select -Expand Result}else{$Obj}
        }}
    End{}
    }
#End


<#
.SYNOPSIS
    New BloodHound Query
.DESCRIPTION
    New BloodHound saved query 
.EXAMPLE
    New-BHPathQuery -Name MySavedQuery -Query "MATCH (x:User) RETURN x LIMIT 1" -Desc "My Saved Query"
#>
function New-BHPathQuery{
    [Alias('New-BHQuery')]
    Param(
        [Parameter(Mandatory=1,ValueFromPipelineByPropertyName)][String]$Name,
        #[Parameter(Mandatory=0,ValueFromPipelineByPropertyName)][String]$Platform='Other',
        #[Parameter(Mandatory=0,ValueFromPipelineByPropertyName)][String]$Category='Custom',
        [Parameter(Mandatory=0,ValueFromPipelineByPropertyName)][String]$Description='Custom Query',
        [Parameter(Mandatory=1,ValueFromPipelineByPropertyName)][String]$Query,
        [Parameter(Mandatory=0)][Switch]$Public,
        [Parameter(Mandatory=0)][Switch]$PassThru
        )
    Begin{NoMultiSession}
    Process{Foreach($Nm in $Name){
        # Body
        $Body = @{
            name  = $Name
            description = $Description
            query = $Query.trim()
            }
        #if($Platform){$Body['Platform']=$Platform}
        #if($Category){$Body['Category']=$Category}
        if($Description){$Body['Description']=$Description}
        $SQ = Invoke-BHAPI api/v2/saved-queries -Method POST -Body ($Body| ConvertTo-Json) -expand data
        if($SQ.id -AND $Public){Set-BHQueryScope -ID $SQ.id -Public}
        if($PassThru){$SQ}
        Start-Sleep -Milliseconds 10
        }}
    End{}
    }
#End


#EOF

## BHAssetGroup [BHZone] // BHAssetGroupSelector [BHSelector]
##############################################################
# Get-BHAssetGroup
# New-BHAssetGroup                                  [BHE Only]
# Set-BHAssetGroup                                  [BHE Only]
# Remove-BHAssetGroup                               [BHE Only]
# Get-BHAssetGroupSelector
# Test-BHAssetGroupSelector
# New-BHAssetGroupSelector
# Set-BHAssetGroupSelector
# Remove-BHAssetGroupSelector
# Get-BHAssetGroupHistory
# Get-BHAssetGroupCertification
# Approve-BHAssetGroupCertification
# Deny-BHAssetGroupCertification
##############################################################

# BHCertificationStatus
enum BHCertificationStatus{
    Pending
    Rejected
    UserCertified
    Automatic
    }

# BHAutoCertify
enum BHAutoCertify{
    Off
    AllObjects
    DirectObjects
    }




<#
.SYNOPSIS
    Get BH Asset Group
.DESCRIPTION
    Get BloodHound Asset Groups
.EXAMPLE
    BHAssetGroup
#>
function Get-BHAssetGroup{
    [Alias('BHZone','Get-BHZone')]
    [CmdletBinding(DefaultParameterSetName='Group')]
    Param(
        [Parameter(Mandatory=1,Position=0,ParameterSetName='Search')]
        [Parameter(Mandatory=1,Position=0,ParameterSetName='Count')]
        [Parameter(Mandatory=1,Position=0,ParameterSetName='Member')]
        [Parameter(Mandatory=0,Position=0,ParameterSetName='Group')][Int]$GroupID,
        #[Parameter(Mandatory=1,ParameterSetName='Search')]
        [Parameter(Mandatory=1,ParameterSetName='Count')]
        [Parameter(Mandatory=1,ParameterSetName='Member')][Switch]$Member,
        [Parameter(Mandatory=1,ParameterSetName='Count')][Switch]$Count,
        [Parameter(Mandatory=1,Position=1,ParameterSetName='Search')][String]$AssetID,
        [Parameter(Mandatory=0,ParameterSetName='Search')][Switch]$Selector
        )
    if(-Not$GroupID){BHAPI /asset-group-tags -Expand data.tags}
    else{if($Count){BHAPI /asset-group-tags/$GroupID/members/counts -Expand data.counts}
        elseif($AssetID){
            $Exp=if($Selector){'data.member.selectors'}else{'data.member'}
            BHAPI /asset-group-tags/$GroupID/members/$AssetID -Expand $exp}
        elseif($Member){BHAPI /asset-group-tags/$GroupID/members -Expand data.members}
        else{BHAPI /asset-group-tags/$GroupID -Expand data.tag}
        }
    }
#End



<#
.SYNOPSIS
    New BH Asset Group
.DESCRIPTION
    Create BloodHound Asset Group
.EXAMPLE
    New-BHAssetGroup -Name MyAssetGroup -type Label
#>
function New-BHAssetGroup{
    [Alias('New-BHZone')]
    Param(
        [Parameter(Mandatory=1)][String]$Name,
        [ValidateSet('Tier','Label')]
        [Parameter(Mandatory=0)][String]$Type='Label',
        [Parameter(Mandatory=0)][String]$Description='Privilege Zone',
        [Parameter(Mandatory=0)][int]$Position,
        #[Parameter(Mandatory=0)][Switch]$DisableAnalysis,
        [Parameter(Mandatory=0)][Switch]$RequireCertiFy
        )
    NoMultiSession;BHEOnly
    if(($Type -eq 'Label') -AND ('Position' -IN $PSCmdlet.MyInvocation.BoundParameters.Keys)){
        Write-Warning "[BH] Asset group position only applies to Tiers. Remove -Position or set -Type Tier";RETURN
        }
    $AssGrp = @{
        name            = $Name
        type            = Switch($Type){Tier{1}Label{3}}
        description     = $Description
        require_certify = if($RequireCertify){$true}else{$false}
        }
    #$AssGrp['analysis_enabled']=if($Type -eq 'label' -OR $DisableAnalysis){$False}else{$True}
    if('Position' -IN $PSCmdlet.MyInvocation.BoundParameters.Keys){
        $AssGrp['position'] = $Position
        }
    $AssGrp = $AssGrp | ConvertTo-Json -Depth 21
    BHAPI api/v2/asset-group-tags POST $AssGrp -Expand $Null
    }
#End


<#
.SYNOPSIS
    Set BH Asset Group
.DESCRIPTION
    Set BloodHound Asset Group
.EXAMPLE
    Set-BHAssetGroup -Name MyAssetGroup -type Label
#>
function Set-BHAssetGroup{
    [Alias('Set-BHZone')]
    Param(
        [Parameter(Mandatory=0,Position=0)][String]$GroupID,
        [Parameter(Mandatory=0)][String]$Name,
        #[ValidateSet('Tier','Label')]
        #[Parameter(Mandatory=0)][String]$Type,
        [Parameter(Mandatory=0)][String]$Description,
        [Parameter(Mandatory=0)][int]$Position,
        #[Parameter(Mandatory=0)][Bool]$AnalysisEnabled,
        [Parameter(Mandatory=0)][Bool]$RequireCertify
        )
    NoMultiSession;BHEOnly
    #if(($Type -eq 'Label') -AND ('Position' -IN $PSCmdlet.MyInvocation.BoundParameters.Keys)){
    #    Write-Warning "[BH] Asset group position only applies to Tiers. Remove -Position or set -Type Tier";RETURN
    #    }
    $AssGrp = @{}
    if($name){$AssGrp['name'] = $Name}
    #if($type){$AssGrp['type'] = Switch($Type){Tier{0}Label{1}}}
    if($description){$AssGrp['description'] = $Description}
    if('AnalysisEnabled' -IN $PSCmdlet.MyInvocation.BoundParameters.Keys){
        $AssGrp['analysis_enabled'] = $AnalysisEnabled
        }
    if('RequireCertify' -IN $PSCmdlet.MyInvocation.BoundParameters.Keys){
        $AssGrp['require_certify'] = $RequireCertify
        }
    if('Position' -IN $PSCmdlet.MyInvocation.BoundParameters.Keys){
        $AssGrp['position'] = $Position
        }
    if(-Not$AssGrp.keys.count){Write-Warning "[BH] No Parameters passed. Please specify parameter for update";RETURN}
    $AssGrp = $AssGrp | ConvertTo-Json -Depth 21
    BHAPI api/v2/asset-group-tags/$GroupID PATCH $AssGrp -Expand $Null
    }
#End


<#
.SYNOPSIS
    Remove BH Asset Group
.DESCRIPTION
    Remove BloodHound Asset Group
.EXAMPLE
    Remove-BHAssetGroup -id 3 -force
#>
function Remove-BHAssetGroup{
    [Alias('Remove-BHZone')]
    Param(
        [Parameter(Mandatory=1,Position=0)][int]$GroupID,
        [Parameter()][int]$Force
        )
    NoMultiSession;BHEOnly
    if($Force -OR $(Confirm-Action "[BH] Delete Asset Group $GroupID?")){
        BHAPI api/v2/asset-group-tags/$GroupID DELETE
        }
    }
#End

<#
.SYNOPSIS
    Get BH Asset Group Selector
.DESCRIPTION
    Get BloodHound Asset Group Selector
.EXAMPLE
    BHSelector 1 21
#>
function Get-BHAssetGroupSelector{
    [CmdletBinding(DefaultParameterSetName='Selector')]
    [Alias('BHSelector','Get-BHSelector')]
    Param(
        [Parameter(Mandatory=1,Position=0)][Alias('id')][Int]$GroupID,
        [Parameter(Mandatory=1,Position=1,ParameterSetName='Count')]
        [Parameter(Mandatory=1,Position=1,ParameterSetName='Member')]
        [Parameter(Mandatory=1,Position=1,ParameterSetName='SelectorID')][Int]$SelectorID,
        [Parameter(Mandatory=1,ParameterSetName='Count')]
        [Parameter(Mandatory=1,ParameterSetName='Member')][Switch]$Member,
        [Parameter(Mandatory=1,ParameterSetName='Count')][Switch]$Count,
        [Parameter(Mandatory=0,ParameterSetName='SelectorID')][Switch]$Seeds
        )
    if(-Not$SelectorID){BHAPI /asset-group-tags/$GroupID/selectors -Expand data.selectors}
    else{if($Count){
            BHAPI /asset-group-tags/$GroupID/selectors/$selectorID/members -Expand data.members | Group-Object primary_kind -NoElement | Select @{n='primary_kind';e={$_.Name}},count
            }
        elseif($Member){BHAPI /asset-group-tags/$GroupID/selectors/$selectorID/members -Expand data.members}
        else{$Exp = if($Seeds){'data.selector.seeds'}else{'data.selector'}
            BHAPI /asset-group-tags/$GroupID/selectors/$selectorID -Expand $exp
            }
        }
    }
#End

<#
.SYNOPSIS
    Test BH Asset Group Selector
.DESCRIPTION
    Test BloodHound Asset Group Selector
.EXAMPLE
    Test-BHSelector "MATCH (x:User) RETURN x LIMIT 5"
#>
function Test-BHAssetGroupSelector{
    [Alias('Test-BHSelector')]
    Param(
        [Parameter(Mandatory=1,Position=0)][Alias('Value')][String]$Seed,
        [ValidateSet('Cypher','ObjectID')]
        [Parameter(Mandatory=0,Position=1)][Alias('Type')][String]$SeedType='Cypher',
        [Parameter(Mandatory=0)][Switch]$Count
        )
    $SType=Switch($seedType){Cypher{2}ObjectID{1}}
    $Hash=@{seeds=@(@{type=$sType;value=$Seed})}
    BHAPI /asset-group-tags/preview-selectors POST ($Hash|Convertto-Json -Depth 21) -expand data.members
    }
#End

<#
.SYNOPSIS
    New BH Asset Group Selector
.DESCRIPTION
    New BloodHound Asset Group Selector
.EXAMPLE
    New-BHSelector 1 test "MATCH (x:User) RETURN x LIMIT 1"
#>
function New-BHAssetGroupSelector{
    [Alias('New-BHSelector')]
    Param(
        [Parameter(Mandatory=1,Position=0)][String]$GroupID,
        [Parameter(Mandatory=1,Position=1)][String]$Name,
        [Parameter(Mandatory=1,Position=2)][String[]]$Seed,
        [ValidateSet('Cypher','ObjectID')]
        [Parameter(Mandatory=0)][string]$SeedType='Cypher',
        [Parameter(Mandatory=0)][String]$Description,
        # Change to enum
        [Parameter(Mandatory=0)][bool]$AutoCertify=$false
        #[Parameter(Mandatory=0)][bool]$AllowDisable=$true
        )
    $sType = Switch($SeedType){Cypher{2}objectid{1}}
    $Seeds = $Seed|%{@{type=$sType;value=$_}}
    $Hash  = @{
        name  = $Name
        seeds = @($Seeds)
        auto_certify = $AutoCertify -as [Int]
        #allow_disable = $AllowDisable 
        }
    if($Description){$Hash['description']=$Description}
    BHAPI /asset-group-tags/$GroupID/selectors POST $($Hash|Convertto-Json -Depth 21) -expand data
    }


<#
.SYNOPSIS
    Set BH Asset Group Selector
.DESCRIPTION
    Set BloodHound Asset Group Selector
.EXAMPLE
    Set-BHSelector 1 44 -name test
#>
function Set-BHAssetGroupSelector{
    [Alias('Set-BHSelector')]
    Param(
        [Parameter(Mandatory=1,Position=0)][String]$GroupID,
        [Parameter(Mandatory=1,Position=1)][String]$SelectorID,
        [Parameter(Mandatory=0)][String]$Name,
        [Parameter(Mandatory=0)][String[]]$Seed,
        [ValidateSet('Cypher','ObjectID')]
        [Parameter(Mandatory=0)][string]$SeedType,
        [Parameter(Mandatory=0)][String]$Description,
        # Change to Enum
        [Parameter(Mandatory=0)][bool]$AutoCertify,
        [Parameter(Mandatory=0)][bool]$Disabled
        )
    if(($SeedType -AND -NOT$Seed) -OR ($Seed -AND -NOT$SeedType)){
        Write-Warning "[BH] Please Specify Seed and SeedType"
        RETURN
        }
    if($SeedType){$sType=Switch($SeedType){Cypher{2}objectid{1}}}
    if($Seed){$Seeds=$Seed|%{@{type=$sType;value=$_}}}
    $Hash=@{}
    if($Name){$Hash['name']=$Name}
    if($Seed){$Hash['seeds']=$Seeds}
    if($Description){$Hash['description']=$Description}
    if($PSCmdlet.MyInvocation.BoundParameters.keys -contains 'AutoCertify'){$Hash['auto-certify']=$AutoCertify}
    if($PSCmdlet.MyInvocation.BoundParameters.keys -contains 'Disabled'){$Hash['disabled']=$Disabled}
    #$($Hash|Convertto-Json -Depth 21)
    BHAPI /asset-group-tags/$GroupID/selectors/$SelectorID PATCH $($Hash|Convertto-Json -Depth 21) -expand data
    }
#End


<#
.SYNOPSIS
    Remove BH Asset Group Selector
.DESCRIPTION
    Remove BloodHound Asset Group Selector
.EXAMPLE
    Remove-BHSelector 1 44 -force
#>
function Remove-BHAssetGroupSelector{
    [Alias('Remove-BHSelector')]
    Param(
        [Parameter(Mandatory=1)][int]$GroupID,
        [Parameter(Mandatory=1)][int]$SelectorID,
        [Parameter(Mandatory=0)][Switch]$Force
        )
    if($Force -OR $(Confirm-Action "[BH] Delete Selector $SelectorID from Asset Group $GroupID")){
    BHAPI /asset-group-tags/$GroupID/selectors/$SelectorID DELETE
    }}
#End


# ToDo - List kinds ??
# BHAPI api/v2/graphs/kinds -Expand data.kinds <- Not great output (WiP?)... :(

#ToDo <-------------------------- Add proper filtering switches
Function Get-BHAssetGroupHistory{
    [Alias("BHZoneHistory")]
    Param()
    BHAPI asset-group-tags-history -expand data.records
    }
#End


Function Get-BHAssetGroupCertification{
    [Alias('BHZoneCertification','Get-BHZoneCertification')]
    Param(
        [Parameter(Mandatory=0,valueFromPipeline=1)][Alias('id')][String[]]$ZoneID='*',
        [BHCertificationStatus]$Status,
        $limit=0
        )
    Begin{NoMultiSession;BHOnly
        $QParam=@("limit=$Limit")
        if($Status -ne $null){$QParam+="certified=eq:$($Status -as [int])"}
        $BHAG = BHZone -verbose:$false | select id,name
        }
    Process{foreach($Zone in $ZoneID){
        BHAPI asset-group-tags/certifications -expand data.members -Filter $QParam |%{
            [PSCustomObject]@{
                id = $_.id
                Zone = ($BHAG | ? ID -eq $_.asset_group_tag_id).name
                primary_kind = $_.primary_kind
                name = $_.name
                certified = [BHCertificationStatus]$_.Certified 
                object_id = $_.object_id
                environment_id = $_.environment_id
                created_at = $_.created_at
                certified_by = $_.certified_by
                }
            }
        }}
    End{}
    }
#End




# POST action=2 / member_ids[] / note
Function Approve-BHAssetGroupCertification{
    [Alias('Approve-BHZoneCertification')]
    Param(
        [Parameter(Mandatory=1,ValueFromPipelineByPropertyName)][Int[]]$ID,
        [Parameter(Mandatory=0)][String]$Note,
        [Parameter(Mandatory=0)][Switch]$force
        )
    Begin{NoMultiSession;BHEOnly
        [Collections.ArrayList]$Collect = @()
        }
    Process{foreach($Certif in $ID){$Null=$Collect.add($Certif)}}
    End{$Hash = @{
            action     = 2
            member_ids = $Collect
            note       = $Note
            } | ConvertTo-Json -Depth 21
        if($Force -OR $(Confirm-Action "Approve certfication for $($Collect.count) node$(if($Collect.count -gt 1){'s'})")){
            BHAPI asset-group-tags/certifications POST $Hash
            }
        }
    }
#End

# POST action=1 / member_ids[] / note
Function Deny-BHAssetGroupCertification{
    [Alias('Deny-BHZoneCertification')]
    Param(
        [Parameter(Mandatory=1,ValueFromPipelineByPropertyName)][Int[]]$ID,
        [Parameter(Mandatory=0)][String]$Note,
        [Parameter(Mandatory=0)][Switch]$force
        )
    Begin{NoMultiSession;BHEOnly
        [Collections.ArrayList]$Collect = @()
        }
    Process{foreach($Certif in $ID){$Null=$Collect.add($Certif)}}
    End{$Hash = @{
            action     = 1
            member_ids = $Collect
            note       = $Note
            } | ConvertTo-Json -Depth 21
        if($Force -OR $(Confirm-Action "Reject certfication for $($Collect.count) node$(if($Collect.count -gt 1){'s'})")){
            BHAPI asset-group-tags/certifications POST $Hash
            }
        }
    }
#End

######################################################### BHOpenGraph

<## Node Type
Get-BHOpenGraphNodeType [-Nodetype <>]
New-BHOpenGraphNodeType
Set-BHOpenGraphNodeType -Nodetype <>
Remove-BHOpenGraphNodeType -Nodetype <>

## Convert to Ingest format
ConvertTo-BHOpenGraphNode > Custom Node Object Format
ConvertTo-BHOpenGraphEdge > Custom Edge Object Format

New-BHOpenGraphIngestPayload -NodeList <> -EdgeList <>
#>

###############################################

<#
.SYNOPSIS
    Get OpenGraph Node Type
.DESCRIPTION
    Get BloodHound OpenGraph Node Type
.EXAMPLE
    BHOpenGraphType [<$NodeType>] [-Config]
#>
function Get-BHOpenGraphNodeType{
    [Alias('BHOGNodeType','Get-BHOGNodeType')]
    Param(
        [Parameter(Mandatory=0)][Alias('Label','PrimaryKind')][String[]]$NodeType,
        [Parameter(Mandatory=0)][Switch]$Config
        )
    NoMultiSession
    $Exp = if($Config){"data.config.icon"}else{'data'}
    if($NodeType){foreach($NType in $NodeType){BHAPI /custom-nodes/$NType -Expand $exp}}
    else{BHAPI /custom-nodes -Expand $exp}
    }
#End

<#
.SYNOPSIS
    New OpenGraph Node type
.DESCRIPTION
    New BloodHound OpenGraph Node type Configuration
.EXAMPLE
        
#>
function New-BHOpenGraphNodeType{
    [Alias('New-BHOGNodeType')]
    Param(
        [Parameter(Mandatory=1,Position=0,ParameterSetName='Type')][Alias('Label','PrimaryKind')][String]$NodeType,
        [Parameter(Mandatory=0,Position=1,ParameterSetName='Type')][String]$Icon='question',
        [Parameter(Mandatory=0,Position=2,ParameterSetName='Type')][String]$Color='#FFF',
        #[Parameter(Mandatory=0)][String]$IconType='font-awesome',
        [Parameter(Mandatory=1,ValueFromPipeline=1,ParameterSetName='Object')][PSCUstomObject[]]$InputObject
        )
    Begin{
        NoMultiSession
        if($Color){if($Color -notmatch "^\#"){$Color="#$Color"}}
        if($NodeType){[PSCustomObject]@{NodeType=$NodeType;Icon=$Icon;Color=$Color}|New-BHOpenGraphNodeType;Break}
        $Collect=@()
        $IconType='font-awesome'
        }
    Process{foreach($Obj in $InputObject){$Collect+=$Obj}}
    End{$Ctype = $Collect|%{@{"$($_.NodeType)"=@{icon=@{type=$IconType;name=$_.Icon;color=$_.Color}}}}
        BHAPI /custom-nodes POST (@{custom_types=$Ctype}|Convertto-Json -Depth 23) -expand data
        }
    }
#End


<#
.SYNOPSIS
    Set Custom Node type
.DESCRIPTION
    Set BloodHound OpenGraph Node Type Configuration 
.EXAMPLE
    Set-BHOpenGraphType Unknown -IconName question -color '#FFFFFF'
#>
function Set-BHOpenGraphNodeType{
    [Alias('Set-BHOGNodeType')]
    Param(
        [Parameter(Mandatory=1,Position=0)][Alias('Label','PrimaryKind')][String]$NodeType,
        [Parameter(Mandatory=0,Position=1)][String]$Icon,
        [Parameter(Mandatory=0,Position=2)][String]$Color,
        #[Parameter(Mandatory=0)][String]$IconType='font-awesome'
        [Parameter(Mandatory=0)][Switch]$Json
        )
    NoMultiSession
    $IconConf = @{type='font-awesome'}
    if($Icon ){$IconConf['name'] = $Icon}
    if($Color){
        if($Color -notmatch "^\#"){$Color="#$Color"}
        $IconConf['color']= $Color
        }
    $Config = @{config=@{icon=$IconConf}} | Convertto-Json -Depth 23
    if($Json){$Config}
    else{BHAPI /custom-nodes/$NodeType PUT $Config -expand data}
    }
#End



<#
.SYNOPSIS
    Remove OpenGraph Node type
.DESCRIPTION
    Remove BloodHound OpenGraph Node Type Configuration 
.EXAMPLE
    Remove-BHOpenGraphType <$NodeType> [-Force]
#>
function Remove-BHOpenGraphNodeType{
    [Alias('Remove-BHOGNodeType')]
    Param(
        [Parameter(Mandatory=1,Position=0,ValueFromPipelineByPropertyName=1)][Alias('KindName','Label','PrimaryKind')][String[]]$NodeType,
        [Parameter(Mandatory=0)][Switch]$force
        )
    Begin{NoMultiSession}
    Process{Foreach($NType in $NodeType){
        if($Force -OR (Confirm-action "[BH] Delete Custom Node type $Ntype?")){
            BHAPI /custom-nodes/$NType DELETE | Out-Null
            }}}
    End{}###
    }
#End


<#
.SYNOPSIS
    Convert to OpenGraph Node
.DESCRIPTION
    Convert Random Objects to BloodHound OpenGraph Node Format 
.EXAMPLE
    $ObjectList | ToBHOpenGraphNode -Label Person -ExtraLabel CustomNode -NameFrom displayName -ExcludeProps id,displayName
.EXAMPLE
    $ObjectList | ToBHOpenGraphNode *
    If objects already have label,(extralabel),id,name property (ex: Import-Csv)
    Any other props will be used as node property unless -excludeProps is used.
#>
Function ConvertTo-BHOpenGraphNode{
    [Alias('ToBHOGNode')]
    Param(
        [Parameter(Mandatory=1,Position=1,ValueFromPipeline=1)][PSCustomObject[]]$InputObject,
        [Parameter(Mandatory=1,Position=0)][Alias('Label','PrimaryKind')][string]$NodeType,
        [Parameter(Mandatory=0,Position=2)][Alias('ExtraLabel')][string[]]$ExtraType,
        [Parameter(Mandatory=0)][Alias('IDFrom')][string]$ObjectIDfrom,
        [Parameter(Mandatory=0)][string]$NameFrom='Name',
        [Parameter(Mandatory=0)][Alias('Prop')][string[]]$SelectProps='*',
        [Parameter(Mandatory=0)][Alias('xProp')][string[]]$ExcludeProps,
        [Parameter(Mandatory=0,ParameterSetName='RandomID')][Switch]$RandomID
        )
    Begin{}
    Process{Foreach($Obj in $InputObject){
        # NodeType
        if($NodeType -eq '*'){
            $NType=if($Obj.Label){$Obj.Label}
            if($Obj.ExtraLabel){$ExtraType=$Obj.ExtraLabel}
            }
        else{$Ntype=$NodeType}
        # Kinds
        [Collections.ArrayList]$kinds=@($NType)
        if($ExtraType.count){foreach($xType in $extraType){$null=$Kinds.add("$xType")}}
        # Name/ID
        $oName = if($Obj.$NameFrom){"$($Obj.$NameFrom)".toUpper()}Else{Write-Warning "[BH] No Name Property Found. Please specify property to use";RETURN}
        $oID = if($RandomID){"$([GUID]::NewGuid())".toupper()}else{
            if($Obj.$ObjectIDFrom){"$($Obj.$ObjectIDFrom)".toUpper()}
            elseif($Obj.objectid -ne $null){$Obj.objectid.toupper()}
            elseif($Obj.id -ne $null){$Obj.id.toupper()}
            Else{Write-Warning "[BH] No ID Property Found. Please specify property to use";RETURN}
            }
        # Props
        $ExcludeProps += 'objectid'
        $Props = $Obj | Select-Object $SelectProps -exclude $ExcludeProps
        # Objectid/name
        #$Props | Add-Member -MemberType NoteProperty -Name 'objectid' -Value $oID -Force -ea 0
        $Props | Add-Member -MemberType NoteProperty -Name 'name' -Value $oName -Force -ea 0
        # OpenGraph out
        [PSCustomObject]@{
            id         = $oID
            kinds      = $Kinds
            properties = $Props | select name,* -ea 0
            }
        }}
    End{}
    }
#End

<#
.SYNOPSIS
    Convert to OpenGraph Edge
.DESCRIPTION
    Convert Random Objects to BloodHound OpenGraph Edge Format.
    (Use -AllowOrphans when Importing edges without already existing nodes in BHE)
.EXAMPLE
    $RelList | ToBHOpenGraphEdge -Edge CanAbuse -Start <sourceidproperty> -End <targetidproperty>
.EXAMPLE
    $RelList | ToBHOpenGraphEdge  -Edge CanAbuse -TargetByName  -SourceByName -Start <sourcenameproperty> -End <targetnameproperty>
    Will match on name instead of objectid when importing
.EXAMPLE
    $RelList | ToBHOpenGraphEdge -Edge *
    If $RelList objects have source,edge,target property (ex: Import-Csv)
    Any other props will be used as node property unless -excludeProps is used. 
    #>
Function ConvertTo-BHOpenGraphEdge{
    [Alias('ToBHOGEdge')]
    Param(
        [Parameter(Mandatory=1,Position=0)][Alias('kind')][string]$EdgeType,
        [Parameter(Mandatory=0,Position=1)][Alias('Source')][String]$Start='source',
        [Parameter(Mandatory=0,Position=2)][Alias('Target')][String]$End='target',
        [Parameter(Mandatory=0,Position=3)][Alias('Prop')][String[]]$SelectProps='*',
        [Parameter(Mandatory=0)][Alias('xProp')][String[]]$ExcludeProps,
        [Parameter(Mandatory=0)][switch]$SourceByName,
        [Parameter(Mandatory=0)][string]$SourceKind,
        [Parameter(Mandatory=0)][switch]$TargetByName,
        [Parameter(Mandatory=0)][string]$TargetKind,
        [Parameter(Mandatory=0)][Switch]$AllowOrphans,
        [Parameter(Mandatory=1,ValueFromPipeline=1)][PSCustomObject[]]$InputObject
        )
    Begin{}
    Process{Foreach($Obj in $InputObject){
        $srcNode = [PSCustomObject]@{
            value = $(Try{"$($Obj.$Start)".toupper()}Catch{Write-Warning "[BH] Missing Edge Source Value";break})
            match_by = if($SourceByName){'name'}else{'id'}
            }
        if($SourceKind){$srcNode|Add-Member -MemberType NoteProperty -Name 'kind' -Value $SourceKind -force} 
        if($AllowOrphans){$srcNode|Add-Member -MemberType NoteProperty -Name 'allow_orphan' -Value $true} 
        $tgtNode = [PSCustomObject]@{
            value = $(Try{"$($Obj.$End)".toupper()}Catch{Write-Warning "[BH] Missing Edge Target Value";break})
            match_by = if($TargetByName){'name'}else{'id'}
            }
        if($TargetKind){$tgtNode|Add-Member -MemberType NoteProperty -Name 'kind' -Value $TargetKind -force}
        if($AllowOrphans){$tgtNode|Add-Member -MemberType NoteProperty -Name 'allow_orphan' -Value $true}
        $EType = if($EdgeType -eq '*'){if($Obj.edge){$Obj.edge}elseif($Obj.Kind){$Obj.Kind}else{$Obj.Type}}else{$EdgeType}
        $EType = $EType.Substring(0,1).toUpper() + $EType.Substring(1)
        [PSCustomObject]@{
            kind = $EType
            start = $srcNode
            end = $tgtNode
            properties = $Obj | Select-Object $SelectProps -ExcludeProperty $ExcludeProps
            }
        }}
    End{}
    }
#End


<#
.SYNOPSIS
    Convert to OpenGraph Edge
.DESCRIPTION
    Convert Random Objects to BloodHound OpenGraph Edge Format.
    (Use -AllowOrphans when Importing edges without already existing nodes in BHE)
.EXAMPLE
    $InputObj | ToBHOGEdge -Edge CanAbuse -Start @{id='SourceID'} -End @{id='TargetID'} 
.EXAMPLE
    $InputObj| ToBHOGEdge  -Edge CanAbuse -Start @{name='SourceName'} -End @{name='TargetName'} 
    Will match on name instead of id when importing
    #>
Function ConvertTo-BHOpenGraphEdge{
    [Alias('ToBHOGEdge')]
    Param(
        [Parameter(Mandatory=1,Position=0)][Alias('kind')][string]$EdgeType,
        [Parameter(Mandatory=0,Position=1)][Alias('Source')][Hashtable]$StartMatch=@{id='SourceID.toupper()'},
        [Parameter(Mandatory=0,Position=2)][Alias('Target')][Hashtable]$EndMatch=@{id='TargetID.toupper()'},
        [Parameter(Mandatory=0,Position=3)][Alias('Prop')][String[]]$SelectProps='*',
        [Parameter(Mandatory=0)][Alias('xProp')][String[]]$ExcludeProps,
        [Parameter(Mandatory=0)][Alias('aProp')][Hashtable]$AddProps,
        [Parameter(Mandatory=0)][string]$SourceKind,
        [Parameter(Mandatory=0)][string]$TargetKind,
        [Parameter(Mandatory=0)][Switch]$AllowOrphans,
        [Parameter(Mandatory=1,ValueFromPipeline=1)][PSCustomObject[]]$InputObject
        )
    Begin{}
    Process{Foreach($Obj in $InputObject){
        # Source
        $SrcMatch = @()
        Foreach($Key in $StartMatch.Keys){
            $Val = $Obj
            $dot = $StartMatch.$key
            $dot.split('.')|%{if($_ -match "^toupper\(\)$"){$Val=$Val.toupper()}else{$Val=$Val.$_}}
            #if($Key -match "^objectid$|^name$"){$Val=$Val.toupper()}
            $SrcMatch += @{
                key = $Key
                operator = 'equals'
                value = $Val
                }
            }
        $SrcNode = if($SrcMatch.key.count -eq 1 -AND $SrcMatch.key -eq "id"){
            [PSCustomObject]@{
            match_by = $SrcMatch.Key
            value = $SrcMatch.Value
            }}
        else{[PSCustomObject]@{
            match_by = 'property'
            property_matchers = $SrcMatch
            }}
        if($SourceKind){$srcNode|Add-Member -MemberType NoteProperty -Name 'kind' -Value $SourceKind -force} 
        if($AllowOrphans){$srcNode|Add-Member -MemberType NoteProperty -Name 'allow_orphan' -Value $true} 
        # Target
        $TgtMatch = @()
        Foreach($Key in $EndMatch.Keys){
            $Val = $Obj
            $dot = $EndMatch.$key
            $dot.split('.')|%{$val = if($_ -match "^toupper\(\)$"){$Val.toupper()}else{$Val.$_}}
            #if($Key -match "^objectid$|^name$"){$Val=$Val.toupper()}
            $TgtMatch += @{
                key = $Key
                operator = 'equals'
                value = $Val
                }}
        $TgtNode = if($tgtMatch.key.count -eq 1 -AND $tgtMatch.key -eq "id"){
            [PSCustomObject]@{
            match_by = $tgtMatch.Key
            value = $tgtMatch.Value
            }}
        else{[PSCustomObject]@{
            match_by = 'property'
            property_matchers = $TgtMatch
            }}
        if($TargetKind){$tgtNode|Add-Member -MemberType NoteProperty -Name 'kind' -Value $TargetKind -force}
        if($AllowOrphans){$tgtNode|Add-Member -MemberType NoteProperty -Name 'allow_orphan' -Value $true}
        # Edge
        $EType = if($EdgeType -eq '*'){if($Obj.edge){$Obj.edge}elseif($Obj.Kind){$Obj.Kind}else{$Obj.Type}}else{$EdgeType}
        $EType = $EType.Substring(0,1).toUpper() + $EType.Substring(1)
        # EdgeProps
        $EProp = $Obj | Select-Object $SelectProps -ExcludeProperty $ExcludeProps
        Foreach($Key in $AddProps.keys){
            $EProp | Add-Member -MemberType NoteProperty -Name $Key.tolower() -Value $AddProps.$key
            }
        # Output
        [PSCustomObject]@{
            kind = $EType
            start = $srcNode
            end = $tgtNode
            properties = $EProp
            }
        }}
    End{}
    }
#End


<#
.SYNOPSIS
    New OpenGraph Ingest Payload
.DESCRIPTION
    Create BloodHound OpenGraph Ingest Payload with OpenGraph Nodes and/or Edges
    Use ConvertTo-BHOpenGraphNode to format node list
    Use ConvertTo-BHOpenGraphEdge to format Edge list
.EXAMPLE
    BHOpenGraphPayload -NodeList $BHOpenGraphNodeList -EdgeList $BHOpenGraphEdgeList
.EXAMPLE
    # Bulk Import from csv files #
    
    $Graph = @{
        Nodelist = Import-Csv BHOpenGraphCSV\Person.csv | ToBHOpenGraphNode *
        EdgeList = Import-Csv BHOpenGraphCSV\EdgeByID.csv | ToBHOpenGraphEdge *
        }
    
    BHOpenGraphPayload @Graph | BHDataUploadJSON
    
    # Node CSV: id,label,[extralabel],name
    # + any other (treated as node properties)
    # Edge CSV: source,edge,target
    # + any other (treated as edge properties)
    # Edge source and target values should be node IDs
    # (use -SourceFromName and/or -TargetFromName to use name values instead)
#>
Function New-BHOpenGraphIngestPayload{
    [CmdletBinding(DefaultParameterSetName='Arrows')]
    [Alias('BHOGPayload','New-BHOGPayload')]
    Param(
        [Parameter(ParameterSetName='List')][PSCustomObject[]]$NodeList,
        [Parameter(ParameterSetName='List')][PSCustomObject[]]$EdgeList,
        [Parameter()][Switch]$NoJSON,
        [Parameter()][Switch]$Compress,
        [Parameter()][string]$CollectorName='CustomCollector',
        [Parameter()][string]$CollectorVersion='beta',
        [Parameter()][String[]]$CollectionMethod='Custom',
        [Parameter()][string]$SourceKind,
        [Parameter()][Switch]$NoMeta,
        [Parameter(Mandatory=1,ParameterSetName='Arrows',ValueFromPipeline)][String]$FromArrows
        )
    Begin{}
    Process{if($PSCmdlet.ParameterSetName -eq 'List'){
        $Graph = [PSCustomObject]@{}
        #if(-not $fromArrows -AND (-Not$NodeList -AND -not$EdgeList)){Write-Warning "Please specify OpenGraph nodes and/or edges for payload";RETURN}
        if($NodeList){$Graph|Add-Member -MemberType NoteProperty -Name nodes -Value @($NodeList)}
        if($EdgeList){$Graph|Add-Member -MemberType NoteProperty -Name edges -Value @($EdgeList)}
        $Meta = [PSCustomObject]@{
            ingest_version='v1'
            collector=@{
                name    = $CollectorName
                version = $CollectorVersion
                properties = @{collection_methods=@($CollectionMethod)}
                }
            }
        If($SourceKind){$Meta | Add-Member -MemberType NoteProperty -Name source_kind -Value $SourceKind}
        $Out=[PSCUstomObject]@{graph=$Graph<#;metadata=$Meta#>}
        if(-Not$NoMeta){$Out|Add-Member -MemberType NoteProperty -Name metadata -Value $Meta}
        if($NoJSON){$Out}else{$out|Convertto-Json -Depth 23 -Compress:$Compress}
        }}
    End{if($PSCmdlet.ParameterSetName -eq 'Arrows'){
        $arrows = $FromArrows | ConvertFrom-Json -Depth 23
        $arrows = $arrows | Select-Object -ExcludeProperty Style
        #$NodeL = $arrows.nodes | select id,@{n='label';e={$_.labels[0]}},@{n='name';e={if($_.caption){$_.Caption}else{$_.id}}},properties
        $NodeL = foreach($Nd in $arrows.nodes){
            #$Nd | select id,@{n='label';e={$_.labels|select -first 1}},@{n='name';e={if($_.caption){$_.Caption}else{$_.id}}},properties
            $Nd | select id,@{n='Label';e={$_.labels|select -first 1}},@{n='ExtraLabel';e={$_.labels|select -Skip 1}},@{n='name';e={if($_.caption){$_.Caption}else{$_.id}}},properties
            }
        $NodeL = Foreach($nd in $NodeL){
            Foreach($np in ($nd.properties|GM -ea 0|? Membertype -eq Noteproperty).name){$nd|Add-Member -MemberType NoteProperty -Name $np -Value $nd.properties.$np -force}
            $nd
            }
        $NodeL = $NodeL | ToBHOGNode * -ExcludeProps id,label,extraLabel,properties
        $EdgeL = $arrows.relationships | select @{n='source';e={$_.fromId}},@{n='Edge';e={if($_.type){$_.type}else{'IsConnectedTo'}}},@{n='Target';e={$_.toId}}
        $EdgeL = Foreach($ed in $EdgeL){
            Foreach($ep in $($ed.properties|%{$_|GM -ea 0|? Membertype -eq Noteproperty}).name){$ed|Add-Member -MemberType NoteProperty -Name $ep -Value $ed.properties.$ep -force}
            $ed
            }
        $EdgeL = $EdgeL | ToBHOGEdge * -exclude source,edge,target,properties # Props /!\
        $Meta = @{
            CollectorName    = $CollectorName
            CollectorVersion = $CollectorVersion
            CollectionMethod = $CollectionMethod
            }
        if($SourceKind){$Meta['source_kind']=$SourceKind}
        New-BHOpenGraphIngestPayload -NodeList $NodeL -EdgeList $edgeL -NoJSON:$NoJson -Compress:$Compress @Meta
        }}
    }
#End



<#
.SYNOPSIS
    Get OG Extensions
.DESCRIPTION
    Get BloodHound OpenGraph Extensions
.EXAMPLE
    Get-BHOpenGraphExtension
#>
function Get-BHOpenGraphExtension{
    [CmdletBinding()]
    [Alias('BHOGExtension','Get-BHOGExtension')]
    Param()
    BHAPI extensions -Expand data.extensions
    }
#End


<#
.SYNOPSIS
    Upload OG Extension
.DESCRIPTION
    Upload BloodHound OpenGraph Extension
.EXAMPLE
    $ExtensionJson | New-BHOpenGraphExtensionUpload
#>
function New-BHOpenGraphExtensionUpload{
    [CmdletBinding()]
    [Alias('New-BHOGExtension','Upload-BHOGExtension')]
    Param(
        [Parameter(Mandatory=1,ValueFromPipeline=1)][Alias('Schema','Json')][String]$Extension
        )
    Begin{}
    Process{BHAPI extensions POST $Extension}
    End{} 
    }
#End


<#
.SYNOPSIS
    Upload OG Extension
.DESCRIPTION
    Upload BloodHound OpenGraph Extension
.EXAMPLE
    Remove-BHOpenGraphExtensionUpload -ID $ExtensionID [-Force]
#>
function Remove-BHOpenGraphExtension{
    [Alias('Remove-BHOGExtension')]
    Param(
        [Parameter(Mandatory=1,Position=0,ValueFromPipelineByPropertyName=1)][int[]]$ID,
        [Parameter(Mandatory=0)][Switch]$force
        )
    Begin{NoMultiSession
        $ExtensionList = Get-BHOpenGraphExtension | ? is_builtin -eq $False
        }
    Process{Foreach($ExtensionID in $ID){
        $ExtensionName = ($ExtensionList | ? id -eq $ExtensionID).name
        if($Force -OR (Confirm-action "[BH] Delete Extension $ExtensionName")){<#BHAPI /extensions/$ExtensionID DELETE#>}
        }}
    End{}
    }
#End


<#
.SYNOPSIS
    Get OG Edge Type
.DESCRIPTION
    Get BloodHound OpenGraph Edge Types
.EXAMPLE
    Get-BHOpenGraphEdgeType
#>
function Get-BHOpenGraphEdgeType{
    [Alias('BHOGEdgeType','Get-BHOGEdgeType')]
    Param(
        [Parameter(Mandatory=0)][String]$Schema,
        [Parameter(Mandatory=0)][Switch]$IncludeBuiltIn,
        [Parameter(Mandatory=0)][Switch]$Traversable
        )
    $Obj = BHAPI graph-schema/edges -Expand data | sort name
    if($Schema){$Obj = $Obj | ? schema_name -eq $Schema}
    if($Traversable){$Obj = $Obj | ? is_traversable}
    if($IncludeBuiltIn -OR $Schema){$Obj}
    Else{$Obj | ? is_builtin -eq $false | select -ExcludeProperty is_builtin}
    }
#End


<#
.SYNOPSIS
    Get OG SourceKinds
.DESCRIPTION
    Get BloodHound OpenGraph SourceKinds
.EXAMPLE
    Get-BHOpenGraphSourceKind
#>
function Get-BHOpenGraphSourceKind{
    [CmdletBinding()]
    [Alias('BHOGSourceKind','Get-BHOGSourceKind')]
    Param()
    BHAPI /api/v2/graphs/source-kinds -expand data.kinds
    }
#End


<#
.SYNOPSIS
    New OG Extension
.DESCRIPTION
    Create New OG Json Schema
.EXAMPLE
    $OGSchema = New-BHOGSchema GitHub -Prefix GH
#>
function New-BHOpenGraphSchema{
    [Alias('New-BHOGSchema')]
    Param(
        [Parameter(Mandatory=1,Position=0)][Alias('Model')][String]$Name,
        [Parameter(Mandatory=0)][Alias('Prefix')][String]$Namespace,
        [Parameter(Mandatory=0)][String]$Version="0.0.0",
        #[Parameter(Mandatory=0)][String]$Description,        
        #[Parameter(Mandatory=0)][String]$Author='unknown',
        [Parameter(Mandatory=0)][Alias('RootObject')][String]$EnvironmentKind,
        [Parameter(Mandatory=0)][Alias('BaseType')][String]$Sourcekind,
        [Parameter(Mandatory=0)][Alias('IdentityTypes')][String[]]$PrincipalKinds='TBD',
        [Parameter()][Switch]$IncludeFindings
        )
    # Lazy Fix
    if(-Not$Namespace){$Namespace=$Name}
    if(-Not$EnvironmentKind){$EnvironmentKind="${Namespace}_Environment"}
    if(-Not$SourceKind){$SourceKind="${Namespace}_Base"}
    #if(-Not$Description){$Description="This Extension collects $Name objects and relationships"}
    if($EnvironmentKind-notmatch "^${Namespace}_"){$EnvironmentKind="${Namespace}_$EnvironmentKind"}
    if($SourceKind-notmatch "^${Namespace}_"){$SourceKind="${Namespace}_$SourceKind"}
    $PrincipalKinds = Foreach($PKind in $PrincipalKinds){
        if($PKind -notmatch "^${Namespace}_"){$PKind="${Namespace}_$PKind"}
        $PKind
        }
    # Obj
    $Schema = [PSCustomObject]@{
        schema = [PSCustomObject]@{
            name      = $Name
            namespace = $Namespace
            #description = $Description
            #author = $Author
            version   = $Version
            }
        node_kinds = [Collections.ArrayList]@() 
        relationship_kinds = [Collections.ArrayList]@()
        environments = @([PSCustomObject]@{
            environment_kind = $EnvironmentKind
            source_kind      = $Sourcekind
            principal_kinds  = $PrincipalKinds
            })
        relationship_findings = [Collections.ArrayList]@()
        }
    $Schema = If($IncludeFindings){$Schema}else{$Schema|Select-Object -ExcludeProperty relationship_findings}
    $Schema|Convertto-json -depth 21
    }
#End

<#
.SYNOPSIS
    Add OG Schema Node Kind
.DESCRIPTION
    Add OG Node Kind to OG Json Schema
.EXAMPLE
    $OGSchema | Add-BHOGSchemaNode ThisNodeKind
#>
Function Add-BHOpenGraphSchemaNodeKind{
    [Alias('Add-BHOGSchemaNode')]
    Param(
        [Parameter(Mandatory=1,Position=0)][String]$Name,
        [Parameter()][String]$DisplayName,
        [Parameter()][String]$Description='Node description goes here',
        [Parameter()][Bool][Alias('DisplayKind')]$IsDisplayKind=$True,
        [Parameter()][String]$Icon='question-mark',
        [Parameter()][String]$Color='#FFFFFF',
        [Parameter(Mandatory=1,ValueFromPipeline=1)][String]$InputObject
        )
    Process{
        $Obj = $InputObject | Convertfrom-Json -depth 21 -AsHashtable
        $Prefix = $Obj.schema.namespace
        # Lazy Fix
        if($Name -notmatch "^${Prefix}_"){$Name = "${Prefix}_$Name"}
        # Node Def
        $NodeKind = [PSCustomObject]@{
            name            = $Name
            display_name    = if($DisplayName){$DisplayName}else{"$($Obj.schema.name) $($Name.TrimStart("$Prefix").TrimStart("_"))"}
            description     = $Description
            is_display_kind = $IsDisplayKind
            icon            = $Icon
            color           = $Color
            }
        $Obj.node_kinds += $NodeKind
        # Output
        $Obj | ConvertTo-Json -Depth 21
        }    
    }
#End


<#
.SYNOPSIS
    Add OG Schema Edge Kind
.DESCRIPTION
    Add OG Edge Kind to OG Json Schema
.EXAMPLE
    $OGSchema | Add-BHOGSchemaEdge ThisEdge
#>
Function Add-BHOpenGraphSchemaEdgeKind{
    [Alias('Add-BHOGSchemaEdge')]
    Param(
        [Parameter(Mandatory=1,Position=0)][String]$Name,
        [Parameter()][String]$Description='Edge description goes here',
        [Parameter()][Bool][Alias('Traversable')]$IsTraversable=$True,
        [Parameter(Mandatory=1,ValueFromPipeline=1)][String]$InputObject
        )
    Process{
        $Obj = $InputObject | Convertfrom-Json -depth 21 -AsHashtable
        $Prefix = $Obj.schema.namespace
        # Lazy Fix
        if($Name -notmatch "^${Prefix}_"){$Name = "${Prefix}_$Name"}
        # Edge Def
        $EdgeKind = [PSCustomObject]@{
            name           = $Name
            description    = $Description
            is_traversable = $IsTraversable
            }
        $Obj.relationship_kinds += $EdgeKind
        # Finding
        if($Obj.keys -contains "relationship_findings" -AND $IsTraversable){
            $FindingObj = [PSCustomObject]@{
                name = "${Name}_Finding"
                display_name = "$($Obj.schema.name) $($Name.TrimStart("$Prefix").TrimStart("_")) Finding ($Prefix)"
                relationship_kind = $Name
                environment_kind = ($Obj.environments[0]).environment_kind
                remediation = [PSCustomObject]@{
                    short_description = "Short description goes here"
                    long_description  = "Long description goes here"
                    short_remediation = "Short remediation goes here"
                    long_remediation  = "Long remediation goes here"
                    }
                }
            $Obj.relationship_findings += $FindingObj
            }
        # Output
        $Obj | Convertto-json -depth 21
        }
    }
#End


<#
.SYNOPSIS
    Add OG Schema Findings
.DESCRIPTION
    Add OG Findings to OG Json Schema
.EXAMPLE
    $OGSchema | Add-BHOGSchemaFinding
#>
function Add-BHOpenGraphSchemaFinding{
    [Alias('Add-BHOGSchemaFinding')]
    Param(
        [Parameter(Mandatory=1,ValueFromPipeline=1)][String]$InputObject
        )
    Process{
        $Obj = $InputObject | Convertfrom-Json -depth 21 -AsHashtable
        $Prefix = $Obj.schema.namespace
        if(-Not("relationship_findings" -In $Obj.keys)){$Obj["relationship_findings"] = @()}
        $ListF = $Obj.relationship_findings.relationship_kind
        foreach($rel in $Obj.relationship_kinds){
            $Name = $rel.name
            if($Rel.is_traversable -eq 'True' -AND $name -notin $ListF){
                $FindingObj = [PSCustomObject]@{
                    name = "${Name}_Finding"
                    display_name = "$($Obj.schema.name) $($Name.TrimStart("$Prefix").TrimStart("_")) Finding ($Prefix)"
                    relationship_kind = $Name
                    environment_kind = ($Obj.environments[0]).environment_kind
                    remediation = [PSCustomObject]@{
                        short_description = "Short description goes here"
                        long_description  = "Long description goes here"
                        short_remediation = "Short remediation goes here"
                        long_remediation  = "Long remediation goes here"
                        }
                    }
                $Obj.relationship_findings += $FindingObj
                }
            }
        # Output
        $Obj | Convertto-json -depth 21
        }
    }
#End




### BloodHoundOperator - BHUtils
# Read-SecureString
# Confirm-Action
# Get-ErrorWarning
# Read-ZipContent
# Split-Collection
# DynParam
# Format-BHNode


################################################ Read-SecureString

<#
.Synopsis
    Read-SecureString [internal]
.DESCRIPTION
    Read secure string content
.EXAMPLE
    $SecureString | Read-SecureString
#>
function Read-SecureString{
    Param(
        [Parameter(Mandatory,ValuefromPipeline)][Security.SecureString[]]$SecureString
        )
    Begin{}
    Process{Foreach($SecStr in @($SecureString)){
        # Windows_&_7 OR Windows_&_5
        if($PSVersionTable.Platform -eq 'Win32NT' -OR $PSVersionTable.PSEdition -eq 'Desktop'){
            [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecStr)).tostring()
            }
        # Unix_&_7
        else{$SecStr | Convertfrom-SecureString -AsPlainText}
        }}
    End{}
    }
#End



################################################ Confirm-Action

<#
.Synopsis
    Confirm Action [internal]
.DESCRIPTION
    As for action confirmation
.EXAMPLE
    Confirm-Action
#>
function Confirm-Action{
    Param(
        [Parameter(Mandatory=0)]$Action='Are You sure' 
        )
    If($(Read-Host -Prompt "$Action ? (Y/N)") -eq 'Y'){$True}else{$False}
    }
#End



################################################ Get-ErrorWarning

<#
.Synopsis
    Get Error as Warning [internal]
.DESCRIPTION
    Get last error message as warning
.EXAMPLE
    Get-ErrorWarning
#>
function Get-ErrorWarning{
    $errr = $Error[0]
    $errr = try{$errr.ErrorDetails.message | convertfrom-Json -ea 0}Catch{$Errr.Exception.message}
    if($errr.http_status){if($errr.http_status -ne '404'){Write-Warning "$($errr.http_status) - $($errr.errors.message)"}}
    else{Write-Warning $(if($Errr){$Errr}else{'Unknown error... ¯\_(ツ)_/¯'})}
    }
#End



################################################ Read-ZipContent

<#
.Synopsis
    Read Zip Content [internal]
.DESCRIPTION
    Read Zip Content
.EXAMPLE
    ZipRead $Zip
#>
function Read-ZipContent{
    [Alias('ZipRead')]
    Param(
        [Parameter(Mandatory=1)][String]$Zip
        )
    # Add type
    Add-Type -assembly "system.io.compression.filesystem" -ea 0
    # Get item
    $Item = Get-Item $Zip
    # Validate .zip
    if($Item.extension -ne '.zip'){Write-Warning "Invalid file extension";RETURN}
    # OpenRead
    try{$ZipRead = [io.compression.zipfile]::OpenRead($Item.FullName)}catch{RETURN}
    foreach($ZipEntry in $ZipRead.entries){
        $Stream  = $ZipEntry.open()
        $Reader  = New-Object IO.StreamReader($Stream)
        $Content = $Reader.ReadToEnd()
        $Content
        $reader.Close()
        $stream.Close()
        }
    # Dispose Zip
    $ZipRead.Dispose()
    }
#End



################################################ Split-Collection

<#
.Synopsis
   Split-Collection [internal]
.DESCRIPTION
   Split Collection
.EXAMPLE
   0..7 | Split-Collection 3 | ConvertTo-Json -Compress
#>
Function Split-Collection{
    Param(
        [Parameter(Position=0)][int]$Count=0,
        [Parameter(Position=1,valuefromPipeline)][PSObject]$Object
        )
    Begin{$Collect=[Collections.ArrayList]@()}
    Process{foreach($Obj in $Object){$Null=$Collect.add($Obj)}}
    End{if($Count-le 0 -OR $Count -gt $Collect.count){$Count=$Collect.count}
        for($i=0;$i-lt$Collect.count;$i+=$Count){,($Collect[$i..($i+($Count-1))])}
        }}
#####End



################################################ DynParam

<#
.Synopsis
   Get Dynamic Param [Internal]
.DESCRIPTION
   Return Single DynParam to be added to dictionnary
.EXAMPLE
    DynP TestParam String -mandatory 1
#>
function DynParam{
    [CmdletBinding()]
    [Alias('DynP')]
    Param(
        [Parameter(Mandatory=1)][String]$Name,
        [Parameter(Mandatory=1)][string]$Type,
        [Parameter(Mandatory=0)][bool]$Mandat=0,
        [Parameter(Mandatory=0)][int]$Pos=$Null,
        [Parameter(Mandatory=0)][bool]$Pipe=0,
        [Parameter(Mandatory=0)][bool]$PipeProp=0,
        [Parameter(Mandatory=0)]$VSet=$Null,
        [Parameter(Mandatory=0)][String]$Alias
        )
    # Create Attribute Obj
    $Attrb = New-Object Management.Automation.ParameterAttribute
    $Attrb.Mandatory=$Mandat
    $Attrb.ValueFromPipeline=$Pipe
    $Attrb.ValueFromPipelineByPropertyName=$PipeProp
    if($Pos -ne $null){$Attrb.Position=$Pos}
    # Create AttributeCollection
    $Cllct = New-Object Collections.ObjectModel.Collection[System.Attribute]
    # Add Attribute Obj to Collection
    $Cllct.Add($Attrb)
    if($VSet -ne $Null){
        # Create ValidateSet & add to collection
        $VldSt=New-Object Management.Automation.ValidateSetAttribute($VSet)
        $Cllct.Add($VldSt)
        }
    if($Alias){
        # Create ValidateSet & add to collection
        $Als=New-Object Management.Automation.AliasAttribute($Alias)
        $Cllct.Add($Als)
        }
    # Create Runtine DynParam
    $DynP = New-Object Management.Automation.RuntimeDefinedParameter("$Name",$($Type-as[type]),$Cllct)
    # Return DynParam
    Return $DynP
    }
#End


################################################ Format-BHNode [Internal]

<#
.Synopsis
    Format BloodHound Node
.DESCRIPTION
    Format BloodHound Node Object
.EXAMPLE
    BHFormat
#>
function Format-BHNode{
    [Alias('BHFormat')]
    Param(
        [Parameter(Mandatory=1)][PSCustomObject]$Object,
        [Parameter(Mandatory=0)][Alias('NoCount')][Switch]$PropOnly
        )
    if(-Not$Object.props){Write-Warning "Invalid input Object";RETURN}
    $Formated = $Object.props
    if(-Not$PropOnly){
        foreach($Itm in (($object|GM|? membertype -eq Noteproperty).name -ne 'props')){
            $Formated | Add-Member -MemberType NoteProperty -Name $Itm -value $Object.$itm 
            }}
    $Formated
    }
#End



<#
.Synopsis
    [BHE] New BloodHound RRule
.DESCRIPTION
    New BloodHound RRule
.EXAMPLE
    BHRRule
#>
function New-BHRRule{
    [Alias('BHRRule')]
    Param(
        [Parameter()][DateTime]$StartDate=[DateTime]::UTCNow,
        [ValidateSet('MINUTELY','HOURLY','DAILY','WEEKLY','MONTHLY')]
        [Parameter()][String]$Frequency='DAILY',
        [Parameter()][Int]$Interval=1,
        [Parameter()][Int]$Count
        )
    BHEOnly
    $Strt = $startDate.toUniversalTime().tostring('o').replace('.','').replace(':','').replace('-','').trimend('Z')[0..14]-join''
    $RR = "DTSTART:${Strt}Z`nRRULE:FREQ=$Frequency;INTERVAL=$Interval"
    if($Count){$RR+=";COUNT=$Count"}
    RETURN $RR
    }
#End


<#
.Synopsis
    Convert to BloodHound Date
.DESCRIPTION
    Converrt to BloodHound date format
.EXAMPLE
    Get-Date | ToBHDate
#>
function ConvertTo-BHDate{
    [Alias('ToBHDate')]
    Param(
        [Parameter(Mandatory=0,ValueFromPipeline)][DateTime[]]$Date=[DateTime]::utcnow,
        [Parameter()][Switch]$Epoch
        )
    Process{Foreach($dTime in $Date){
        if($Epoch){[Math]::Round(($dtime.toUniversalTime()-[DateTime]::New(1970,1,1,0,0,0,0,0,'utc')).totalmilliseconds,0)}
        else{#[Xml.XmlConvert]::ToString($dTime,[Xml.XmlDateTimeSerializationMode]::Utc)
            $dTime.ToUniversalTime().ToString('o') -replace("0*Z$"),('Z')-replace("\.Z$"),('Z')
            }}}}
#########End


<#
.Synopsis
    Convert from BloodHound Date
.DESCRIPTION
    Converrt from BloodHound date format
.EXAMPLE
    $BHDate | FromBHDate
#>
function ConvertFrom-BHDate{
    [Alias('FromBHDate')]
    Param(
        [Parameter(Mandatory,ValueFromPipeline)][String[]]$Date
        )
    Process{Foreach($dString in $Date){
        if($False){}
        if($dString -match "^(\d{13})$"){[DateTime]::New(1970,1,1,0,0,0,0,0,'utc').AddMilliseconds($dString)}
        else{($dString -as [DateTime]).toUniversalTime()}
        }}}
#####End


<#
.Synopsis
    BHOnly
.DESCRIPTION
    Break if not BHE session
    [Internal] Used at begining of cmdlets
.EXAMPLE
    BHEOnly
#>
function BHEOnly{
    if((BHSession|? x).edition -match 'BHCE'){Write-Warning "BHEOnly - Requires session to BloodHound Enterprise...";Break}
    }
#End


<#
.Synopsis
    NoMultiSession
.DESCRIPTION
    Break if multi-session (use BHScript)
    [Internal] Used at begining of cmdlets
.EXAMPLE
    NoMultiSession
#>
function NoMultiSession{
    if((BHSession|? x).count -gt 1){Write-Warning "NoMultiSession - Please select single session or run BHScript...";Break}
    }
#End


#######################

function Select-Expand{
    [Alias('Expand','dot')]
    Param(
        [Parameter(Mandatory=1,Position=0)][string]$Property,
        [Parameter(Mandatory=1,ValueFromPipeline=1)]$Object
        )
    Begin{}
    Process{
        Foreach($Prop in $Property.split('.')){$Object=$Object.$Prop}
        $Object
        }
    End{}
    }
#End

###########################################
## BloodHound Operator - BHE-Only endpoints
# Approve-BHOperatorEULA
# Start-BHPathFinding
# Get-BHPathFinding
# Approve-BHPathFinding
# Get-BHClient
# New-BHClient
# Set-BHClient
# Remove-BHClient
# New-BHClientToken
# New-BHCLientJob
# Get-BHClientJob
# Remove-BHClientJob
# Get-BHEvent
# New-BHEvent
# Set-BHEvent
# Remove-BHEvent
# Get-BHDataPosture

enum BHFindingType{
    ASREPRoasting
    AzureNonT0ManagedIdentityAssignment
    AzureT0AddMembers
    AzureT0AddOwner
    AzureT0AddSecret
    AzureT0AKSContributor
    AzureT0AppAdmin
    AzureT0AutomationContributor
    AzureT0AvereContributor
    AzureT0CloudAppAdmin
    AzureT0Contributor
    AzureT0ExecuteCommand
    AzureT0GetCerts
    AzureT0GetKeys
    AzureT0GetSecrets
    AzureT0KeyVaultContributor
    AzureT0LogicAppContributor
    AzureT0MGAddMember
    AzureT0MGAddOwner
    AzureT0MGAddSecret
    AzureT0MGGrantAppRoles
    AzureT0MGGrantRole
    AzureT0Owner
    AzureT0Owns
    AzureT0ResetPassword
    AzureT0RoleActivationNoMFA
    AzureT0SyncedToEntraUser
    AzureT0UserAccessAdministrator
    AzureT0VMAdminLogin
    AzureT0VMContributor
    AzureT0WebsiteContributor
    Kerberoasting
    LargeDefaultGroupsAddAllowedToAct
    LargeDefaultGroupsAddKeyCredentialLink
    LargeDefaultGroupsAddMember
    LargeDefaultGroupsAddSelf
    LargeDefaultGroupsAdmins
    LargeDefaultGroupsAllExtendedRights
    LargeDefaultGroupsCoerceAndRelayNTLMToADCS
    LargeDefaultGroupsCoerceAndRelayNTLMToLDAP
    LargeDefaultGroupsCoerceAndRelayNTLMToLDAPS
    LargeDefaultGroupsCoerceAndRelayNTLMToSMB
    LargeDefaultGroupsDCOM
    LargeDefaultGroupsForceChangePassword
    LargeDefaultGroupsGenericAll
    LargeDefaultGroupsGenericWrite
    LargeDefaultGroupsManageCA
    LargeDefaultGroupsManageCertificates
    LargeDefaultGroupsOwns
    LargeDefaultGroupsOwnsLimitedRights
    LargeDefaultGroupsPSRemote
    LargeDefaultGroupsRDP
    LargeDefaultGroupsReadGMSA
    LargeDefaultGroupsReadLAPS
    LargeDefaultGroupsSQLAdmin
    LargeDefaultGroupsSyncLAPSPassword
    LargeDefaultGroupsWriteAccountRestrictions
    LargeDefaultGroupsWriteDacl
    LargeDefaultGroupsWriteGPLink
    LargeDefaultGroupsWriteOwner
    LargeDefaultGroupsWriteOwnerLimitedRights
    LargeDefaultGroupsWriteSPN
    NonT0DCSyncers
    T0ADCSESC1
    T0ADCSESC10a
    T0ADCSESC10b
    T0ADCSESC13
    T0ADCSESC3
    T0ADCSESC4
    T0ADCSESC6a
    T0ADCSESC6b
    T0ADCSESC9a
    T0ADCSESC9b
    T0AddAllowedToAct
    T0AddKeyCredentialLink
    T0AddMember
    T0AddSelf
    T0Admins
    T0AllExtendedRights
    T0AllowedToAct
    T0AllowedToDelegate
    T0CoerceAndRelayNTLMToADCS
    T0CoerceAndRelayNTLMToLDAP
    T0CoerceAndRelayNTLMToLDAPS
    T0CoerceAndRelayNTLMToSMB
    T0CoerceToTGT
    T0DCOM
    T0DumpSMSA
    T0ForceChangePassword
    T0GenericAll
    T0GenericWrite
    T0GoldenCert
    T0HasSIDHistory
    T0Logins
    T0ManageCA
    T0ManageCertificates
    T0MarkSensitive
    T0Owns
    T0OwnsLimitedRights
    T0PSRemote
    T0RDP
    T0ReadGMSA
    T0ReadLAPS
    T0SQLAdmin
    T0SyncedToADUser
    T0SyncLAPSPassword
    T0WriteAccountRestrictions
    T0WriteDACL
    T0WriteGPLink
    T0WriteOwner
    T0WriteOwnerLimitedRights
    T0WriteSPN
    }
#End

enum BHJobStatus{
    Ready
	Running
	Complete
	Canceled
	TimedOut
	Failed
	Ingesting
	Analyzing
	PartialyComplete
    }
#End

# BHEOnly ################################################ BHOperatorEULA

<#
.Synopsis
    [BHE] Approve BloodHound EULA
.DESCRIPTION 
    Approve BloodHound Eneterprise End User License Agreement
.EXAMPLE
    Approve-BHOperatorEULA
#>
function Approve-BHOperatorEULA{
    [CmdletBinding()]
    Param()
    NoMultiSession;BHEOnly
    BHAPI api/v2/accept-eula
    }
#End



# BHEOnly ################################################ BHPathFinding

<#
.Synopsis
    [BHE] Start BloodHound Path Finding
.DESCRIPTION
    Start BloodHound Attack Path Analysis
.EXAMPLE
    Start-BHPathFinding
#>
function Start-BHPathFinding{
    [CmdletBinding()]
    [Alias('BHPathAnalysis')]
    Param()
    BHEOnly
    $Null = BHAPI -Method PUT api/v2/attack-paths
    }
#End


<#
.Synopsis
    [BHE] Get BloodHound Path Finding
.DESCRIPTION
    Get BloodHound Attack Path Finding
.EXAMPLE
    BHFinding -TypeList
.EXAMPLE
    BHFinding -ListAvail -DomainID $ID
.EXAMPLE
    BHFinding -Detail -DomainID $ID -Type Kerberoasting
.EXAMPLE
    BHSearch Domain | BHFinding -Trend -Verbose -start (date).adddays(-10)
#>
function Get-BHPathFinding{
    [CmdletBinding(DefaultParameterSetName='Detail')]
    [Alias('BHFinding')]
    Param(
        [Parameter(Mandatory,ParameterSetName='ListAll')][Alias('ListAll')][Switch]$TypeList,
        [Parameter(Mandatory,ParameterSetName='Avail')][Switch]$ListAvail,
        [Parameter(Mandatory=0,ParameterSetName='Detail')][Switch]$Detail,
        [Parameter(Mandatory,ParameterSetName='Spark')][Switch]$Sparkline,
        [Parameter(Mandatory,ParameterSetName='Trend')][Switch]$Trend,
        [Parameter(ParameterSetName='Detail')]
        [Parameter(ParameterSetName='Spark')][Alias('Type')][BHFindingType[]]$FindingType,
        [Parameter(ParameterSetName='Trend',Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName=1,Position=0)]
        [Parameter(ParameterSetName='Spark',Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName=1,Position=0)]
        [Parameter(ParameterSetName='Detail',Mandatory=0,ValueFromPipeline,ValueFromPipelineByPropertyName=1,Position=0)]
        [Parameter(ParameterSetName='Avail',Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName=1,Position=0)][Alias('ID','objectid')][String[]]$DomainID,
        [Parameter(ParameterSetName='Trend')]
        [Parameter(ParameterSetName='Spark')][Datetime]$StartDate,
        [Parameter(ParameterSetName='Trend')]
        [Parameter(ParameterSetName='Spark')][Datetime]$EndDate,
        [Parameter(ParameterSetName='Spark')]
        [Parameter(ParameterSetName='Detail')][Int]$Limit=$($BHSession|? x|select -last 1).limit
        )
    Begin{BHEOnly
        $DomList=[Collections.ArrayList]@()
        if($PSCmdlet.ParameterSetName -eq 'ListAll'){BHAPI api/v2/attack-path-types -expand data}
        }
    Process{Foreach($DomID in $DomainID){
        if($PSCmdlet.ParameterSetName -ne 'trend'){$FindType = if(-Not$FindingType.count){BHAPI api/v2/domains/$DomID/available-types -expand data}else{$FindingType}}
        Switch($PSCmdlet.ParameterSetName){
                Avail {$FindType}
                Detail{[Array]$qFilter=@()
                    if($Limit){$qFilter+="limit=$Limit"}
                    Foreach($fType in $FindType){BHAPI api/v2/domains/$DomID/details -filter "finding=$fType",$qFilter -expand data}
                    }
                Spark{[Array]$qFilter=@()
                    if($StartDate){$qFilter+="from=$($StartDate|ToBHDate)"}
                    if($EndDate){$qFilter+="to=$($EndDate|ToBHDate)"}
                    Foreach($fType in $FindType){
                        $Out = BHAPI api/v2/domains/$DomID/sparkline -filter "finding=$fType",$qFilter -expand data
                        if($Limit){$Out |Select -first $Limit}else{$Out}
                        }
                    }
                Trend{$Null=$DomList.add($DomID)}
                }}}
    End{if($PSCmdlet.ParameterSetName -eq 'trend'){
        [Array]$qFilter=@()
        if($StartDate){$qFilter+="start=$($StartDate|ToBHDate)"}
        if($EndDate){$qFilter+="end=$($EndDate|ToBHDate)"}
        Foreach($Dom in $DomList){$qFilter+="environments=$Dom"}
        BHAPI api/v2/attack-paths/finding-trends -Filter $qfilter -Expand Data.findings
        }
    elseif($PSCmdlet.ParameterSetName -eq 'detail' -AND -Not$DomainID){
        BHAPI 'api/v2/attack-paths/details' -Expand data.findings
        }}
    }
#End


function Get-BHPathFindingInfo{
    [Alias('BHFindingInfo')]
    Param(
        [Parameter(ValueFromPipeline=1)][BHFindingType[]]$FindingType,
        [Parameter()][Switch]$Full,
        [Parameter()][Alias('md')][Switch]$OutMarkDown
        )
    Begin{BHEOnly}
    Process{foreach($Ftype in "$FindingType"){
        $FDoc = [PSCustomObject]@{
            Finding = $FType
            Title   = BHAPI "api/v2/assets/findings/$Ftype/title.md"
            Type   = BHAPI "api/v2/assets/findings/$Ftype/type.md"
            Description = BHAPI "api/v2/assets/findings/$Ftype/short_description.md"
            Remediation = BHAPI "api/v2/assets/findings/$Ftype/short_remediation.md"
            References   = BHAPI "api/v2/assets/findings/$Ftype/references.md"
            }
        if($Full){
            $fDesc = BHAPI "api/v2/assets/findings/$Ftype/long_description.md"
            $fRem  = BHAPI "api/v2/assets/findings/$Ftype/long_remediation.md"
            $FDoc | Add-Member -MemberType NoteProperty -Name Description_Full -Value $FDesc
            $FDoc | Add-Member -MemberType NoteProperty -Name Remediation_Full -Value $FRem
            }
        if($OutMarkDown){"# $($FDoc.Title.trim())
**$($FDoc.Type.trim()) - $FType**

## Description
$(if($Full){$FDoc.Description_Full.split("`r`n").replace("##",'###')}else{$FDoc.Description})

## Remediation
$(if($Full){$FDoc.Remediation_Full.split("`r`n").replace("##",'###')}else{$FDoc.Remediation})

## References
$($FDoc.References)
`r`n</br>`r`n
---"}
        else{$FDoc}
        }}
    End{}
    }
#End

<#
.Synopsis
    [BHE] Approve BloodHound Path Finding
.DESCRIPTION
    Approve BloodHound Path Finding
.EXAMPLE
    Approve-BHPathFinding -ID $id [-Force]
#>
function Approve-BHPathFinding{
    [Alias('Approve-BHFinding')]
    Param(
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)][Alias('PathID')][Int[]]$ID,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)][Alias('finding')][BHFindingType]$FindingType,
        [Parameter(Mandatory)][Bool]$Accepted,
        [Parameter()][DateTime]$Until=$([DateTime]::utcnow.AddDays(30)),
        [Parameter()][Switch]$Force,
        [Parameter()][Switch]$PassThru
        )
    Begin{NoMultiSession;BHEOnly}
    Process{foreach($PathId in $ID){
    if($Force -OR $(Confirm-Action "Confirm Acceptance:$Accepted for Finding ID $PathID")){
        $Accept = @{
            risk_type    = "$FindingType"
            accepted     = $Accepted
            accept_until = if($Until -AND $Accepted){$Until|ToBHDate}
            } | Convertto-Json
        $Out = BHAPI api/v2/attack-paths/$PathID/acceptance PUT $Accept -expand data
        if($PassThru){$Out}
        }}}
    End{}
    }
#EOF




# BHEOnly ################################################ BHClient

<#
.Synopsis
    [BHE] Get BloodHound Client
.DESCRIPTION
    Get BloodHound Client
.EXAMPLE
    Get-BHClient -ID $ClientID
.EXAMPLE
    Get-BHClient -ID $ClientID -CompletedJobs
#>
function Get-BHClient{
    [CmdletBinding(DefaultParameterSetName='All')]
    [Alias('BHClient')]
    Param(
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,ParameterSetName='ID')][Alias('ClientID')][String[]]$ID,
        [Parameter(ParameterSetName='ID')][Switch]$CompletedJobs
        )
    Begin{BHEOnly
        if(-Not$ID){BHAPI "api/v2/clients?hydrate_domains=false&hydrate_ous=false" -expand Data}else{NoMultiSession}
        }
    Process{Foreach($CliID in $ID){
        if($CompletedJobs){BHAPI api/v2/clients/$CliID/completed-jobs -expand data}
        else{BHAPI api/v2/clients/$CliID -expand Data}
        }}
    End{}
    }
#End


<#
.Synopsis
    [BHE] New BloodHound Client
.DESCRIPTION
    New BHE Client
.EXAMPLE
    $Client = @{
        Prop = value
        }
    New-BHClient @Client
#>
function New-BHClient{
    Param(
        [Parameter(Mandatory=1,ValueFromPipeline)][String[]]$Name,
        [ValidateSet('SharpHound','AzureHound')]
        [Parameter(Mandatory=1)][Alias('Type')][String]$ClientType,
        [Parameter(Mandatory=0)][Alias('DC')][String]$DomainController
        #[Parameter(Mandatory=0)][PSObject[]]$EventList
        )
    Begin{NoMultiSession;BHEOnly}
    Process{Foreach($CLiName in $Name){
        $ClientObj = @{
            name = $CliName
            type = $ClientType.tolower()
            events = @()
            } 
        if($DomainController){$ClientObj['domain_controller'] = $DomainController}    
        $ClientObj = $ClientObj | ConvertTo-Json
        $Output = BHAPI api/v2/clients POST $ClientObj -expand data
        if($Output){
            $Output.token.key = $Output.token.key | ConvertTo-SecureString -AsPlainText -force
            $Output
            }
        }}
    End{}
    }
#End

<#
.Synopsis
    [BHE] Set BloodHound Client
.DESCRIPTION
    Description
.EXAMPLE
    Example
#>
function Set-BHClient{
    Param(
        [Parameter(Mandatory=1)][String]$ID,
        [Parameter(Mandatory=0)][String]$Name,
        [Parameter(Mandatory=0)][Alias('DC')][String]$DomainController
        )
    NoMultiSession;BHEOnly
    $ClientObj = BHAPI clients/$ID -expand data -wa stop
    $ClientSet = @{
        name = if($Name){$Name}else{$ClientObj.Name}
        domain_controller = if($DomainController){$DomainController}else{$ClientObj.domain_controller}
        }
    BHAPI clients/$ID PUT $ClientSet
    }
#End

<#
.Synopsis
    [BHE] Remove-BloodHound Client
.DESCRIPTION
    Description
.EXAMPLE
    Example
#>
function Remove-BHClient{
    Param(
        [Parameter(Mandatory,ValuefromPipeline,ValuefromPipelineByPropertyName)][Alias('ClientID')][String]$ID,
        [Parameter()][Switch]$Force
        )
    Begin{NoMultiSession;BHEOnly}
    Process{Foreach($CliID in $ID){
        if($Force -OR $(Confirm-Action "Delete BHClient ID $ID")){
            $Null = BHAPI api/v2/clients/$ID DELETE
            }}}
    End{}###
    }
#End



## BHClientToken

<#
.Synopsis
    [BHE] New BloodHound Client Token
.DESCRIPTION
    New BHE Client Token
.EXAMPLE
    New-BHClientToken -id $ClientID [-Force]
#>
function New-BHClientToken{
    Param(
        [Parameter(Mandatory,ValuefromPipelineByPropertyName)][Alias('ClientID')][String[]]$ID,
        [Parameter()][Switch]$AsPlainText,
        [Parameter()][Switch]$Force
        )
    Begin{NoMultiSession;BHEOnly}
    Process{foreach($CliID in $ID){
        if($Force -OR $(Confirm-Action "Generate $(if($AsPlainText){'Plaintext '})Token for Client $CliID")){
        $Output = BHAPI clients/$ID/token PUT -expand data
        if($Output -AND -Not$AsPlainText){$Output.key=$Output.key|ConvertTo-SecureString -AsPlainText -Force
            $Output|Add-Member -MemberType NoteProperty -Name client_id -Value $CliID
            }
        $Output
        }}}
    End{}
    }
#End




## BHClientJob

<#
.Synopsis
    [BHE] Start BloodHound Client Job
.DESCRIPTION
    Start BHE Client Job (immediate task)
.EXAMPLE
    Start-BHClientJob
#>
function Start-BHClientJob{
    [Alias('Start-BHJob')]
    Param(
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)][Alias('ID')][String[]]$ClientID,
        [Parameter(Mandatory=0)][Switch]$SessionCollection,
        [Parameter(Mandatory=0)][Switch]$LocalGroupCollection,
        [Parameter(Mandatory=0)][Switch]$ADStructureCollection,
        [Parameter(Mandatory=0)][Switch]$CertServiceCollection,
        [Parameter(Mandatory=0)][Switch]$CARegistryCollection,
        [Parameter(Mandatory=0)][Switch]$DCRegistryCollection,
        [Parameter(Mandatory=0)][Switch]$AllDomain,
        [Parameter(Mandatory=0)][String[]]$OU,
        [Parameter(Mandatory=0)][String[]]$Domain,
        [Parameter(Mandatory=0)][Switch]$Force
        )
    Begin{BHEOnly
        $EvtObj = @{
            session_collection       = [bool]$SessionCollection
            local_group_collection   = [bool]$LocalGroupCollection
            ad_structure_collection  = [bool]$ADStructureCollection
            cert_services_collection = [bool]$CertServiceCollection
            ca_registry_collection   = [bool]$CARegistryCollection
            dc_registry_collection   = [bool]$DCRegistryCollection
            all_trusted_domains      = [bool]$AllDomain
            ous                      = @($OU)
            domains                  = @($Domain)
            } | ConvertTo-Json
        }
    Process{Foreach($CliID in $ClientID){
        if($Force -OR $(Confirm-Action "Run collection Client ID $CliID")){BHAPI -Method POST api/v2/clients/$CliID/jobs -Body $EvtObj -expand data}
        }}
    End{}
    }
#End

<#
.Synopsis
    [BHE] Get BloodHound Client Job
.DESCRIPTION
    Get BloodHound Client Finished Job
    Job Status:
    Invalid          =-1
    Ready            = 0
	Running          = 1
	Complete         = 2
	Canceled         = 3
	TimedOut         = 4
	Failed           = 5
	Ingesting        = 6
	Analyzing        = 7
	PartialyComplete = 8
.EXAMPLE
    Get-BHClientJob [-status <status>] [-ClientID <client_id>]
.EXAMPLE
    BHJob -IncludeUnfinished [-Only]
.EXAMPLE
    BHJob -JobId 1234 [-log]
#>
function Get-BHClientJob{
    [CmdletBinding(DefaultParameterSetName='Finished')]
    [Alias('BHJob')]
    Param(
        [Parameter(Mandatory=0,ValueFromPipelineByPropertyName,ParameterSetName='Unfinished')]
        [Parameter(Mandatory=0,ValueFromPipelineByPropertyName,ParameterSetName='Finished')][Alias('id')][string[]]$ClientID="*",
        [Parameter(Mandatory=0,ParameterSetName='Unfinished')]
        [Parameter(Mandatory=0,ParameterSetName='Finished')][int]$Status,
        [Parameter(Mandatory=0,ParameterSetName='Finished')][Int]$Limit=$($BHSession|? x|select -last 1).limit,
        [Parameter(Mandatory=1,ParameterSetName='Unfinished')][Alias('Unfinished')][Switch]$IncludeUnfinished,
        [Parameter(Mandatory=0,ParameterSetName='Unfinished')][Switch]$Only,
        [Parameter(Mandatory=1,ParameterSetName='ID')][String]$JobID,
        [Parameter(Mandatory=0,ParameterSetName='ID')][Switch]$Logs
        )
    Begin{BHEOnly}
    process{Switch($PSCmdlet.ParameterSetName){
        Unfinished{
            foreach($CliID in $ClientID){
                [Array]$qFilter=@('hydrate_ous=false','hydrate_domains=false')    
                #if($Limit){$qFilter+="limit=$Limit"}
                if($Status){$qFilter+="status=eq:$Status"}
                if($CliID -AND $CliID -ne '*'){$qFilter+="client_id=eq:$CliID"}
                $Jobz=BHAPI jobs -Filter $qFilter -expand data |%{$_|Add-member -MemberType NoteProperty -Name status -Value ($_.status -as [BHJobStatus]) -force -PassThru}
                if($Only){$Jobz|? status -in ('Ready','Running','Canceled','TimedOut','Failed') |Sort-Object execution_time -Descending}else{$Jobz|Sort-Object execution_time -Descending}
                }
            }
        Finished{
            foreach($CliID in $ClientID){
                [Array]$qFilter=@('hydrate_ous=false','hydrate_domains=false')
                if($Limit){$qFilter+="limit=$Limit"}
                if($Status){$qFilter+="status=eq:$Status"}
                if($CliID -AND $CliID -ne '*'){$qFilter+="client_id=eq:$CliID"}
                BHAPI jobs/finished -Filter $qFilter -expand data |%{$_|Add-member -MemberType NoteProperty -Name status -Value ($_.status -as [BHJobStatus]) -force -PassThru}
                }
            }
        ID{if($Logs){BHAPI jobs/$JobID/log}else{BHAPI jobs/$JobID -expand data}}
        }}
    End{}
    }
#End


<#
.Synopsis
    [BHE] Remove BloodHound Client Job
.DESCRIPTION
    Description
.EXAMPLE
    Remove-BHClientJob -Id $JobId
#>
function Remove-BHClientJob{
    [Alias('Remove-BHJob')]
    Param(
        [Parameter(Mandatory,ValuefromPipeline,ValueFromPipelineByPropertyName)][String]$ID,
        [Switch]$Force
        )
    Begin{NoMultiSession;BHEOnly}
    Process{if($Force -OR $(Confirm-Action "Delete BHE Job ID $ID")){
        BHAPI api/v2/jobs/$ID/cancel PUT
        }}
    End{}
    }
#End



# BHEOnly ################################################ BHEvent

<#
.Synopsis
    [BHE] Get BloodHound Client Event
.DESCRIPTION
    Description
.EXAMPLE
    Get-BHEvent
#>
function Get-BHEvent{
    Param(
        [Parameter(Mandatory=1,ParameterSetName='ID')][String[]]$EventID,
        [Parameter(Mandatory=0,ValueFromPipeline,ValueFromPipelineByPropertyName,ParameterSetName='All')][Alias('ID')][String[]]$ClientID
        )
    Begin{BHEOnly
        if($EventID){Foreach($EvtID in $EventID){BHAPI events/$EvtID -expand data}}

        }
    Process{if($ClientID){Foreach($CliID in $ClientID){BHAPI api/v2/events -filter "client_id=eq:$CliID" -expand Data}}}
    End{if(-Not$ClientID -AND -NOT $EventID){BHAPI api/v2/events -expand Data}}
    }

<#
function New-BHEvent{
    Param(
        [Parameter(Mandatory=1,ValueFromPipelineByPropertyName)][Alias('ID')][String[]]$ClientID,
        [Parameter(Mandatory=0)][String]$Rule=$(BHRRule),
        [Parameter(Mandatory=0)][Switch]$SessionCollection,
        [Parameter(Mandatory=0)][Switch]$LocalGroupCollection,
        [Parameter(Mandatory=0)][Switch]$ADStructureCollection,
        [Parameter(Mandatory=0)][Switch]$CertServiceCollection,
        [Parameter(Mandatory=0)][Switch]$CARegistryCollection,
        [Parameter(Mandatory=0)][Switch]$DCRegistryCollection,
        [Parameter(Mandatory=0)][Switch]$AllDomain,
        [Parameter(Mandatory=0)][String[]]$OU,
        [Parameter(Mandatory=0)][String[]]$Domain
        )
    Begin{NoMultiSession;BHEOnly}
    Process{Foreach($CliID in $ClientID){
        $EventObj = $(@{
            client_id                = $CliID
            rrule                    = $Rule
            session_collection       = [bool]$SessionCollection
            local_group_collection   = [bool]$LocalGroupCollection
            ad_structure_collection  = [bool]$ADStructureCollection
            cert_services_collection = [bool]$CertServiceCollection
            ca_registry_collection   = [bool]$CARegistryCollection
            dc_registry_collection   = [bool]$DCRegistryCollection
            all_trusted_domains      = [bool]$AllDomain
            ous                      = @($OU)
            domains                  = @($Domain)
            } | ConvertTo-Json -Compress).replace("[null]","[]")
        BHAPI events POST $EventObj -expand data
        }}
    End{}
    }
#End
#>

<#
.Synopsis
    [BHE] New BloodHound Client Event
.DESCRIPTION
    Description
.EXAMPLE
    New-BHEvent
#>
function New-BHEvent{
    Param(
        [Parameter(Mandatory=0,ValueFromPipelineByPropertyName)][Alias('ID')][String[]]$ClientID,
        [Parameter(Mandatory=0)][String]$Rule=$(BHRRule),
        [Parameter(Mandatory=0)][Switch]$SessionCollection,
        [Parameter(Mandatory=0)][Switch]$LocalGroupCollection,
        [Parameter(Mandatory=0)][Switch]$ADStructureCollection,
        [Parameter(Mandatory=0)][Switch]$CertServiceCollection,
        [Parameter(Mandatory=0)][Switch]$CARegistryCollection,
        [Parameter(Mandatory=0)][Switch]$DCRegistryCollection,
        [Parameter(Mandatory=0)][Switch]$AllDomain,
        [Parameter(Mandatory=0)][String[]]$OU,
        [Parameter(Mandatory=0)][String[]]$Domain
        )
    Begin{NoMultiSession;BHEOnly}
    Process{
        $EventObj = @{rrule = $Rule}   
        if($SessionCollection){$EventObj['session_collection']=[bool]$SessionCollection}
        if($LocalGroupCollection){$EventObj['local_group_collection']=[bool]$LocalGroupCollection}
        if($ADStructureCollection){$EventObj['ad_structure_collection']=[bool]$ADStructureCollection}
        if($CertServiceCollection){$EventObj['cert_services_collection']=[bool]$CertServiceCollection}
        if($CARegistryCollection){$EventObj['ca_registry_collection']=[bool]$CARegistryCollection}
        if($DCRegistryCollection){$EventObj['dc_registry_collection']=[bool]$DCRegistryCollection}
        if($AllDomain){$EventObj['all_trusted_domains']=[bool]$AllDomain}
        if($OU.count){$EventObj['ous']=@($OU)}
        if($Domain.count){$EventObj['domains']=@($Domain)}
        Foreach($CliID in $ClientID){
            $EventObj['client_id']=$CliID 
            BHAPI events POST ($EventObj|Convertto-Json) -expand data
            }
        }
    End{if(-Not$ClientID){$EventObj}}
    }
#End


<#
.Synopsis
    [BHE] Set BloodHound Client Event
.DESCRIPTION
    Description
.EXAMPLE
    Set-BHEvent
#>
function Set-BHEvent{
    Param(
        [Parameter(Mandatory=1,ValueFromPipelineByPropertyName)][String[]]$ID,
        [Parameter(Mandatory=0)][String]$Rule,
        [Parameter(Mandatory=0)][bool]$SessionCollection,
        [Parameter(Mandatory=0)][bool]$LocalGroupCollection,
        [Parameter(Mandatory=0)][bool]$ADStructureCollection,
        [Parameter(Mandatory=0)][bool]$CertServiceCollection,
        [Parameter(Mandatory=0)][bool]$CARegistryCollection,
        [Parameter(Mandatory=0)][bool]$DCRegistryCollection,
        [Parameter(Mandatory=0)][bool]$AllDomain,
        [Parameter(Mandatory=0)][String[]]$OU,
        [Parameter(Mandatory=0)][String[]]$Domain,
        [Parameter()][Switch]$PassThru
        )
    Begin{NoMultiSession;BHEOnly
        $Invocation = $PSCmdlet.MyInvocation.BoundParameters
        }
    Process{foreach($EvtId in $ID){# <------------------------------- Confirm Action?
        $EvtObj = BHEvent -Eventid $EvtID
        if($EvtObj){$EvtSet = @{
            rrule                    = if($Rule){$Rule}else{$EvtObj.rrule}
            session_collection       = if($Invocation.ContainsKey("SessionCollection")){$SessionCollection}else{$EvtObj.session_collection}
            local_group_collection   = if($Invocation.ContainsKey("LocalGroupCollection")){$LocalGroupCollection}else{$EvtObj.local_group_collection}
            ad_structure_collection  = if($Invocation.ContainsKey("ADStructureCollection")){$ADStructureCollection}else{$EvtObj.ad_structure_collection}
            cert_services_collection = if($Invocation.ContainsKey("CertServiceCollection")){$CertServiceCollection}else{$EvtObj.cert_services_collection}
            ca_registry_collection   = if($Invocation.ContainsKey("CARegistryCollection")){$CARegistryCollection}else{$EvtObj.ca_registry_collection}
            dc_registry_collection   = if($Invocation.ContainsKey("DCRegistryCollection")){$DCRegistryCollection}else{$EvtObj.dc_registry_collection}
            all_trusted_domains      = if($Invocation.ContainsKey("AllDomain")){$AllDomain}else{$EvtObj.all_trusted_domains}
            ous                      = if($OU){$OU}else{$EvtObj.ous}
            domains                  = if($Domain){$Domain}else{$EvtObj.domains} 
            } | ConvertTo-Json
        $Output = BHAPI events/$ID PUT $EvtSet -expand data
        if($PassThru){$Output}
        }}}
    End{}
    }
#End

<#
.Synopsis
    [BHE] Remove BloodHound Client Event
.DESCRIPTION
    Description
.EXAMPLE
    Remove-BHEvent $EventID
#>
function Remove-BHEvent{
    Param(
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)][String]$ID,
        [Switch]$Force
        )
    Begin{NoMultiSession;BHEOnly}
    Process{if($Force -OR $(Confirm-Action "Delete BloodHound Event ID $ID")){$Null=BHAPI api/v2/events/$ID DELETE}}
    End{}
    }
#End


# BHEOnly ################################################ BHDataPosture

<#
.Synopsis
    [BHE] Get BloodHound Data Posture
.DESCRIPTION
    Get BloodHound Data Posture
.EXAMPLE
    Get-BHDataPosture
.EXAMPLE
    BHSearch Domain test | BHPosture -Exposure -StartDate (date).adddays(-30)

#>
function Get-BHDataPosture{
    [CmdletBinding(DefaultParameterSetName='General')]
    [Alias('BHPosture')]
    Param(
        [Parameter(Mandatory=1,ValueFromPipelineByPropertyName)][Alias('ID','ObjectID')][String[]]$DomainID,
        [Parameter(Mandatory=1,ParameterSetName='Exposure')][Switch]$Exposure,
        [Parameter(Mandatory=1,ParameterSetName='Finding')][Switch]$Findings,
        [Parameter(Mandatory=1,ParameterSetName='Asset')][Switch]$Assets,
        [Parameter(Mandatory=1,ParameterSetName='Group')][Switch]$GroupCompleteness,
        [Parameter(Mandatory=1,ParameterSetName='Session')][Switch]$SessionCompleteness,
        [Parameter(ParameterSetName='General')][Int]$Limit=1,
        [Parameter(ParameterSetName='Exposure')]
        [Parameter(ParameterSetName='Finding')]
        [Parameter(ParameterSetName='Asset')]
        [Parameter(ParameterSetName='Group')]
        [Parameter(ParameterSetName='Session')]
        [Parameter(ParameterSetName='General')][Alias('From')][Datetime]$StartDate,
        [Parameter(ParameterSetName='Exposure')]
        [Parameter(ParameterSetName='Finding')]
        [Parameter(ParameterSetName='Asset')]
        [Parameter(ParameterSetName='Group')]
        [Parameter(ParameterSetName='Session')]
        [Parameter(ParameterSetName='General')][Alias('To')][Datetime]$EndDate
        )
    Begin{BHEOnly
        $DomList = [Collections.ArrayList]@()
        [Array]$qFilter=@() ## /!\ Date filter /!\
        if($StartDate){$qFilter+=if($PSCmdlet.ParameterSetName -eq 'General'){"from=$($StartDate|ToBHDate)"}else{"start=$($StartDate|ToBHDate)"}}
        if($EndDate){$qFilter+=if($PSCmdlet.ParameterSetName -eq 'General'){"to=$($EndDate|ToBHDate)"}else{"end=$($EndDate|ToBHDate)"}}
        }
    Process{foreach($DomID in $DomainID){
        Switch($PSCmdlet.ParameterSetName){
            General {
                $qFilter+="limit=$Limit"
                $qfilter+="domain_sid=eq:$DomID"
                BHAPI api/v2/posture-stats -filter $qFilter -expand data
                }
            Default{$Null=$DomList.add($DomID)}
            }}}
    End{Foreach($Dom in $DomList){$qFilter+="environments=$Dom"}
        Switch($PSCmdlet.ParameterSetName){
            Exposure{BHAPI api/v2/posture-history/exposure -Filter $qfilter -expand data}
            Finding {BHAPI api/v2/posture-history/findings -Filter $qfilter -expand data}
            Asset   {BHAPI api/v2/posture-history/assets -Filter $qfilter -expand data}
            Group   {BHAPI api/v2/posture-history/group-completeness -Filter $qfilter -expand data}
            Session {BHAPI api/v2/posture-history/session-completeness -Filter $qfilter -expand data}
            }
        }
    }
#End

# BHEOnly ################################################ BHEntityMeta

<#
.Synopsis
    [BHE] Get BloodHound Entity Meta
.DESCRIPTION
    Get BHE Entity Meta
.EXAMPLE
    BHMeta <objectID>
#>
function Get-BHNodeMeta{
    [Alias('BHMeta')]
    Param(
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,Position=0)][Alias('objectid')][String[]]$ID
        )
    Begin{BHEOnly}
    Process{foreach($ObjID in $ID){
        BHAPI meta/$ObjID -expand data
        }}
    End{}
    }
#End


# EOF

#EOF