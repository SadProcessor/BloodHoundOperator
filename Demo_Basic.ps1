Break # Do not run as script
######################################
## BloodHoundOperator Demo - Basics ##
######################################

# Load Module
. ./BloodHoundOperator.ps1

############################################### Install
## Install BloodHound 
New-BHComposer -Composer BHCE -IncludeEnv -IncludeConfig
cd BHCE
Invoke-BHComposer Up


# --> Login via UI / Change Password / Create API Token



############################################### Connect
$BHTokenID = Get-Clipboard
$BHTokenKey = Get-Clipboard | ConvertTo-SecureString -AsPlainText -Force
## New Session
New-BHSession -TokenID $BHTokenID -Token $BHTokenKey

# Check session
Get-BHSession

# Set session
Set-BHSession -Limit 10000 -Timeout 60 -CypherClip
BHSession


############################################### API
# Docs
Get-BHAPI
Get-BHAPI | select-object method,route,summary | sort-object route

# Invoke BHAPI (used under the hood by other cmdlets)
Invoke-BHAPI -Method GET -URI /api/v2/bloodhound-users
Invoke-BHAPI -Method GET -URI api/v2/bloodhound-users | Select -Expand data | Select -Expand users
BHAPI bloodhound-users -dot data.users
# Equiv Wrapper
Get-BHOperator
BHOperator

############################################### Help
Get-Help Get-BHOperator
Help New-BHSession -Examples 
Get-Command *-BH*
Get-Command BHOperator -Syntax

BHHelp | ft
BHHelp -Online
BHHelp -TierZero | ft
BHHelp -TierZero -online


############################################### User Management
## Operator (= BloodHound user)
# Get Operator
Get-BHOperator
BHOperator -Self

# Roles & Perms
Get-BHOperatorRole | ft
BHRole -self
BHRole | ? name -eq 'power user' | select -expand permissions | ft
BHRole | ? name -eq 'upload-Only' | select -expand permissions | ft
Get-BHOperatorPermission | ft

# Create User
$UserRole = BHRole | ? name -eq "user"
New-BHOperator -Name alice -Email 'alice@bhoperator.demo' -Role $UserRole.id
$Alice = BHOperator | ? principal_name -eq alice
$Alice

# Set Password
$DemoPwd = 'Dem0Passw0rd!'
$Alice | Set-BHOperatorSecret -Secret $DemoPwd -RequireReset -Force
# Set User props
$Alice | Set-BHOperator -FirstName alice -LastName wonderland -Role (BHRole | ? name -eq "Power User").id -passthru -verbose

# Disable User
$Alice | Disable-BHOperator -PassThru

# Remove User
$Alice | Remove-BHOperator 
BHOperator | ? principal_name -eq alice



# Create Upload-Only User
$UploadRole = BHRole | ? name -eq 'upload-only'
New-BHOperator -Name UploadDog -Role $UploadRole.id

# Create API Token
$Secret = Get-BHOperator | ? principal_name -eq UploadDog | New-BHOperatorToken -TokenName ApiUploadOnly
$Secret
$Secret.key
$Secret.key | Read-SecureString # Ooops! 

# Revoke Token
Revoke-BHOperatorToken -TokenID $Secret.id -Force

# Create new token
$Secret = BHOperator | ? principal_name -eq UploadDog | New-BHOperatorToken -TokenName ApiUploadOnly -Force

# Create Session
New-BHSession -TokenID $Secret.id -Token $Secret.Key
BHSession | ft
# Whoami
(BHOperator -Self).principal_name
BHRole -Self

# Call
BHAPI bloodhound-users -expand data.users # Computer says no...
# Switch session
Select-BHSession -ID 1
# Call
BHAPI bloodhound-users -expand data.users # Computer says yes...



################################################################ Data & Ingestion
# Collector
Get-BHDataCollector
# Import-BHDataCollector     ## Watch for Defender!!

# Import Data
$Zip = get-item ~\infected\BHCE\SampleData\StarWars\StarWars1.zip
Invoke-BHDataUpload -Data $Zip -Verbose
BHDataAnalysis

# Check Upload
Get-BHDataUpload

# Split Json [Experiemntal]
$zip | Invoke-BHDataUpload -split 20 -Verbose
Get-BHDataUpload -Limit 10 | ft

BHData -ListDomain | ft
BHData -id S-1-5-21-928081958-2569533466-1777930793
BHData -Platform AD


################################################# Nodes & Edges

## Node Search
Search-BHNode -Label User | ft
Search-BHNode -Label User -Keyword yoda
BHSearch User yoda -verbose
BHSearch User yoda,chewbacca -verbose


## Node
# Search
BHNode -search User yoda -Verbose
BHNode User -search yoda
# ID
BHNode User -id 'S-1-5-21-928081958-2569533466-1777930793-1800'
'S-1-5-21-928081958-2569533466-1777930793-1800' | BHNode User
# multiple
BHNode User -search -1800,-1799 -PropOnly | ft
BHSearch User '-1800','-500' | BHNode User -PropOnly

# Expand Lists
BHNode user -search yoda 
BHNode user -search yoda -list Memberships | ft
BHNode user -search yoda -list Memberships -AsPath | ft

BHNode Computer -search deathstar
BHNode Computer -search deathstar -list Controllers | ft
BHNode Computer -search deathstar -list Controllers -AsPath | ft

## NodeGroup (aka Asset Group)
Get-BHNodeGroup

$TIerZero = BHNodeGroup | ? name -eq 'Admin Tier Zero'

BHNodeGroup $TIerZero.id -Member | Select primary_kind,name,object_id
BHNodeGroup $TIerZero.id -Member | ? custom_member | ft # None

$CustomT0 = 'Yoda','Chewbacca'

# Add to NodeGroup
BHSearch User $CustomT0 | Add-BHNodeToNodeGroup -NodeGroupID $TierZero.id
# BHDataAnalysis

BHNodeGroup $TIerZero.id -Member | ? custom_member | select primary_kind,name,object_id
BHSearch User $CustomT0 

# Remove
BHSearch User $CustomT0 | Remove-BHNodeFromNodeGroup -NodeGroupID $TierZero.id -force -Verbose
#BHDataAnalysis
BHSearch User $CustomT0 | fl




## Path
Get-BHPath -Shortest -Source User -target "Group{name:'DOMAIN ADMINS@STARWARS.LOCAL'}" | ft
BHPath -Source User -target "Group{name:'DOMAIN ADMINS@BSTARWARS.LOCAL'}" -Edge 'MemberOf'
BHPath -Source User -Edge AdminTo -target Computer | ft
BHPath -x User -r AdminTo -y Computer | ft
BHPath -x User -r AdminTo -y Computer -yWhere "y.name='DEATHSTAR.STARWARS.LOCAL'" | ft
BHPath -x User -r AdminTo -y Computer -yWhere "y.name='DEATHSTAR.STARWARS.LOCAL'" -cypher # Paste in UI


## Custom Queries (like CypherDog)
BHPath "MATCH (x:Group)
MATCH (y:Computer) 
MATCH p=shortestPath((x)-[r:MemberOf|AdminTo*1..]->(y))
RETURN p" | ft


## Saved Queries
Get-BHPathQuery
$Demo = New-BHPathQuery -Name 'DemoQuery' -Query "MATCH (n) RETURN n LIMIT 10"
$Demo # +Show in UI

BHCypher $Demo.query | ft

Get-BHPathQuery
$Demo | Remove-BHPathQuery
Get-BHPathQuery



############################################# BHE
$BHE = @{
    Server  = '<InstanceName>.bloodhoundenterprise.io'
    TokenID = $BHETokenID
    Token   = $BHETokenKey
    }
New-BHSession @BHE
BHSession |ft
BHOperator -self


## BHCLient (Collectors)
Get-BHClient | ft
$DemoClient = New-BHClient -Name DemoClient -ClientType AzureHound -Verbose
$DemoClient
$DemoClient | New-BHEvent
$ClientToken = $DemoClient | New-BHClientToken
Get-BHClient -ID $DemoClient.id
$ClientToken

Remove-BHClient -ID $DemoClient.id -Force
Get-BHClient -ID $DemoClient.id


## Stats
BHSearch Domain | ft
BHSearch Domain BAD.lab
BHSearch Domain BAD.lab | BHData

## BHPosture
BHSearch Domain BAD.lab | BHPosture

BHSearch Domain | BHPosture | ft

BHSearch Domain BAD.lab | BHPosture -Limit 20 | ft


## BHFinding
BHFinding -TypeList

BHSearch Domain BAD.lab | BHFinding -ListAvail

BHSearch Domain BAD.lab | BHFinding -Detail -FindingType T0GenericAll -Limit 10 | ft

$Lookback = [Datetime]::utcnow.AddDays(-3)
BHSearch Domain BAD.lab | BHFinding -Sparkline -FindingType T0GenericAll -StartDate $Lookback | ft

BHSearch Domain | BHFinding -Sparkline -StartDate $Lookback | ft


############################################## Composition
BHSearch Domain ESC9.LOCAL | BHFinding -Detail -FindingType T0ADCSESC9b

BHPath "MATCH p=(:Group)-[:ADCSESC9b]->(:Domain{name:'ESC9.LOCAL'}) RETURN p" | ft
BHPath "MATCH p=(:Group)-[:ADCSESC9b]->(:Domain{name:'ESC9.LOCAL'}) RETURN p" -Cypher | Set-clipboard # + Show composition in UI

BHPath "MATCH p=(:Group)-[:ADCSESC9b]->(:Domain{name:'ESC9.LOCAL'}) RETURN p" | select -last 1 | ft
BHPath "MATCH p=(:Group)-[:ADCSESC9b]->(:Domain{name:'ESC9.LOCAL'}) RETURN p" | select -last 1 | BHComposition | ft


############################################# Multi-Session (Experimental)
Select-BHSession 1,3
BHSession | ft
BHOperatorRole -self

Select-BHsession -None
# That's all folks...

################################################################

###################################################### Uninstall
# Kill all 
BHComposer Down #-Force
BHComposer KillAll #-Force
# BHComposer Update



####################################################################
####################################################################
## Dog Whispering Reloaded - Arroooo! ##

<#
# Batch create BH Users from csv

# Domain stats as table with total

# Add list of nodes to Tier0 / Tier0 to csv per domain

# Compare controllable y/x

# Bulk upload custom queries

# Rotate all API keys & user password

# Pull Metrics and push to SIEM (Sentinel)

# BloodHound + BHOperator + Pester = hot!

#>

#################################################################### Setup

# Load Module
. ./BloodHoundOperator.ps1
# Create Sessions
# BHCE
New-BHSession -TokenID $BHTokenID -Token $BHTokenKey #<- Must be secure string
# BHE
New-BHSession -Server test.bloodhoundenterprise.io -TokenID $BHETokenID -Token $BHETokenKey
# Check
Get-BHSession | ft





############################################################################
# 1- Create BH Users from csv [in BHCE]
Select-BHSession 1

# Get User List
$UserList = Import-Csv ~\ArooCon\UserCreate.csv
# Get Role List
$RoleList = Get-BHOperatorRole | select-Object Id,Name
# Create Users
$NewUsers = Foreach($Usr in $UserList){
    # User Props
    $UserProps = @{
        Name      = $Usr.Name
        FirstName = $Usr.FirstName
        LastName  = $Usr.LastName
        Email     = $Usr.Email
        Role      = $RoleList | Where Name -eq $Usr.Role | select -expand id
        }
    # Create user
    New-BHOperator @UserProps -PassThru -verbose
    }
# Set Password
$NewUsers.data | Set-BHOperatorSecret -Secret "ArooConDem0!" -RequireReset -Force -verbose

# Oneliner
Import-Csv ~\ArooCon\UserCreate.csv |%{New-BHOperator -Name $_.Name -FirstName $_.FirstName -LastName $_.LastName -Email $_.email -Role (BHRole|? name -eq $_.Role).id -PassThru} | Set-BHOperatorSecret -Secret "ArooConDem0!" -Force -RequireReset

# CHeck
BHOperator

################################################################################
# 2- All domain stats as table per domain with total [in BHE]
Select-BHSession 2

# List all Domains
$AllDomain = Get-BHData -ListDomain | ? type -eq active-directory
# Get Stat
$DomainStats = $AllDomain | BHData | Select @{n='domain';e={($AllDomain|? id -eq $_.domain_sid).Name}},Users,Computers,Groups,Relationships
# Get Total 
$DomainStats += BHData -Platform AD | Select @{n='domain';e={'All'}},Users,Computers,Groups,Relationships
# Table
$DomainStats | Sort relationships -descending | Out-GridView

################################################################################
# Add list of users to Tier0 & Tier0 to csv [local]
Select-BHSession 1

# Get User list
$AddToT0 = Get-Content ~\ArooCon\AddToT0.txt
# Get Tier0
$T0Group = BHNodeGroup | ? name -eq 'Admin Tier Zero' 
# Add to tier0
BHSearch User $AddToT0 | Add-BHNodeToNodeGroup -NodeGroupID $T0Group.id
# BHDataAnalysis
Start-BHDataAnalysis
# Export T0 to csv
BHNodeGroup -ID $T0Group.id -Member | Select -Exclude kinds | Export-Csv -Path ~\ArooCon\T0Export.csv -Force


################################################################################
# Compare memberships of this and that user [Local]

# Get lists
$ChewbaccaGroup = BHNode -Search User Chewbacca -list Memberships
$YodaGroup      = BHNode -Search User Yoda -list Memberships
# Compare
Compare-Object $ChewbaccaGroup.name $YodaGroup.name -IncludeEqual




################################################################################
# Bulk upload custom queries [Local]

# Query List (import from json/yaml/csv/xml/...)
$MyQueryList = $(
    [PSCustomObject]@{Name = 'OneUser'    ; Query = "MATCH (x:User) RETRUN X LIMIT 1"    }
    [PSCustomObject]@{Name = 'OneComputer'; Query = "MATCH (x:Computer) RETRUN X LIMIT 1"}
    # more...
    )
# Import
$MyQueryList | New-BHQuery

# Check
BHQuery | ft


################################################################################
# Rotate all user passwords & API keys (except admin) [Local]
$UserList = BHOperator | Where principal_name -ne admin

## All user must change Password next logon if they had one (except admin)
$UserList | where AuthSecret | Set-BHOperatorSecret -Secret "DefaultPassword123!" -RequireReset -Force

## Rotate API keys for all users if they had one (except admin) and ouput list of new keys to table
# Revoke old
$UserList | Where {$_|Get-BHOperatorToken} | Get-BHOperatorToken | Revoke-BHOperatorToken -Force
# Create New
$KeyList = foreach($Usr in $UserList){$Usr|New-BHOperatorToken -TokenName $Usr.Name -AsPlainText -Force}


################################################################################
# Pull data and push to SIEM (Sentinel) [Test]
Select-BHSession 2

$LastID = 0
While(1){
    # Pull
    $ThisData = BHSearch Domain BAD.LAB | BHPosture | Select -exclude updated_at,deleted_at
    # Push
    if($ThisData.id -gt $LastID){
        {Invoke-AzWriter -LogType BloodHoundEnterprise -EventID BHPosture -Message "BloodHound Posture Stats" -Property @{Data=$ThisData|Convertto-json}}
        }
    # Set LastID
    $LastID = $Last.id
    # Sleep
    Start-sleep -Duration (New-TimeSpan -Secondes 5)
    }


################################################################################
# BloodHound + BHOperator + Pester >> Write atomic audit tests against BH Database [Local]
# Idea came after watching F. Bader (DE) present Maester at PSConfEU
Select-BHSession -id 1

# Unsupported OS
Describe 'Test: Computer with unsupported OS'{
    $OSlist=(
        'XP',
        'Vista',
        '7',
        '8.1'
        # add more...
        )
    Foreach($OS in $OSList){
        it "No Computers are running Windows $OS" {
            $testQ = "MATCH (x:Computer) WHERE x.operatingsystem CONTAINS ' $OS' RETURN x"
            $testResult = BHCypher $TestQ -wa SilentlyContinue
            $TestResult.count | should be 0 
            }
        }
    }

# Test Tier0 Violation 
Describe 'Test: Tier Zero violation'{
    it 'No T0 Logon to non-T0 Computer'{
        $testResult = BHCypher "MATCH p=(:Computer)-[:HasSession]->(:User) RETURN p" | Where IsTierZeroViolation
        $TestResult.count | should be 0 
        }
    }




###################################################### Domain Trust Overview

# Trust Overview
Invoke-BHCypher "MATCH p=(:Domain)-[:TrustedBy]->(:Domain) RETURN p"
|%{[PSCustomObject]@{
    TrustedDomain  = $_.Source
    Edge           = $_.Edge
    TrustingDomain = $_.Target
    TrustType      = $_.EdgeProps.TrustType
    Transitive     = $_.EdgeProps.Transitive
    SIDFiltering   = $_.EdgeProps.SidFiltering
    }}
|Format-Table



## Completness overview per domain
Foreach($ThisDomain in (BHSearch domain)){
    $ThisDomain | BHData | Add-Member -MemberType NoteProperty -Name domain -Value $ThisDomain.name -PassThru 
    | Select domain,computers,session_completeness,local_group_completeness
    }