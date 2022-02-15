# Settings
#$DllPath = "C:\\Program Files\\ESET\\RemoteAdministrator\\Server\\"
$verbose = $false

#set log file to use
$timeStamp = Get-Date -Format "yyyy.MM.dd_HH.mm.ss.ffff"
$global:myLogFldr = "$($PSScriptRoot)\Logs"
$global:myLog = "$($global:myLogFldr)\$($timeStamp)_$($($MyInvocation.MyCommand.Name).Split(".")[0]).log"
#Make Log folder
If ((Test-Path -Path $($global:myLogFldr) -Type Container) -eq $False) {
	New-Item -Path $($global:myLogFldr) -ItemType Directory
}

Function myLogger() {
    param (
    [string]$myStr,
    [validateSet('info','warn','threat')][string]$warnLvl="info",
    [string]$logFile=$global:myLog
    )
    $myStr | Out-File -LiteralPath $logFile -Append
    If ($warnLvl -eq "info") {
        Write-host $myStr
    } ElseIf ($warnLvl -eq "warn") {
        Write-host $myStr -ForegroundColor Yellow
    } ElseIf ($warnLvl -eq "threat") {
        Write-host $myStr -ForegroundColor DarkRed
    }
    
}


#Ignore SSL Errors
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Functions
<#
function sendRequest($Request) {
    $Response = $Null
    [ServerApi]::era_process_request($Request,[ref]$Response)
    return $Response | ConvertFrom-Json
}
#>
function authenticate ($authLoginReq) {
	myLogger -myStr "Connecting to EEI Host $($EsmcHost) with Username $($Esmcuser)"
    $response = Invoke-WebRequest -Method PUT -Uri "https://$($EsmcHost)/api/v1/authenticate" -Body ($authLoginReq | ConvertTo-Json) #-SkipCertificateCheck #this skip cert switch only works on v7 Powershell(possibly on v6)
	#clear out any credentials
	$authLoginReq = $Null
	$global:LoginReq = $Null
    If ($response.StatusCode -eq 200) {
        #return ($response.headers)
		#return $response
        return ($response.headers['X-Security-Token'])
    } Else {
        myLogger -myStr "Failed to authenticate.  Received HTTP Error: $($response.StatusCode)" -warnLvl "threat"
		exit
    }
}

function getRules ($reqQuery) {
	$response = Invoke-WebRequest -Method GET -Uri "https://$($EsmcHost)/api/v1/rules" -Body $reqQuery -Headers @{'Authorization' = 'Bearer '+$token}  #-SkipCertificateCheck #this skip cert switch only works on v7 Powershell(possibly on v6)
    If ($response.StatusCode -eq 200) {
        #return ($response.headers)
        return $response
    } Else {
        myLogger -myStr "Failed to get rules.  Received HTTP Error: $($response.StatusCode)" -warnLvl "threat"
		exit
    }
}


function getRule ($id) {
	    $response = Invoke-WebRequest -Method GET -Uri "https://$($EsmcHost)/api/v1/rules/$id" -Body $reqQuery -Headers @{'Authorization' = 'Bearer '+$token}  #-SkipCertificateCheck #this skip cert switch only works on v7 Powershell(possibly on v6)
    If ($response.StatusCode -eq 200) {
        #return ($response.headers)
        return $response
    } Else {
        myLogger -myStr  "Failed to get rule.  Received HTTP Error: $($response.StatusCode)" -warnLvl "threat"
		exit
    }
}

function enableDisableRule ($reqQuery) {
		#myLogger -myStr  "myQuery 0: $($reqQuery[0])"
		#myLogger -myStr  "myQuery 1: $($reqQuery[1])"
		#myLogger -myStr  "myID: $($id[1])"
	    $response = Invoke-WebRequest -Method PATCH -Uri "https://$($EsmcHost)/api/v1/rules/$($reqQuery[0])" -Body ($reqQuery[1] | ConvertTo-Json) -Headers @{'Authorization' = 'Bearer '+$token}  #-SkipCertificateCheck #this skip cert switch only works on v7 Powershell(possibly on v6)
		#response 204 = Success
    If ($response.StatusCode -eq 204) {
        #return ($response.headers)
        return $response
    } Else {
        return "Failed to Enable/Disable rule.  Received HTTP Error: $($response.StatusCode)"
    }
}


#function to get server version from "serverinfo.js"
function getSvrVer () {
	myLogger -myStr "`r`nGrabbing EEI Server Version from https://$($EsmcHost)/serverinfo.js"
	$response = Invoke-WebRequest -Method GET -Uri "https://$($EsmcHost)/serverinfo.js"  #-SkipCertificateCheck #this skip cert switch only works on v7 Powershell(possibly on v6)
    If ($response.StatusCode -eq 200) {
        #return ($response.headers)
        return (((($response.content -split("`r`n") | Select-String -Pattern '"version": ').ToString().Trim(",")) -split (": "))[1]).Trim('"')
		#clear;$content -match '"version": "1.6.1755.0",';$matches[0].TrimEnd(",").Split(":")[1].Trim().TrimStart('"').TrimEnd('"')
    } Else {
        myLogger -myStr  "Failed to get rule.  Received HTTP Error: $($response.StatusCode)" -warnLvl "threat"
		return $null
    }
}

function promptSvrVer () {
	myLogger -myStr "Unable to obtain server version from server.  Prompting...`r`n" -warnLvl "warn"
	myLogger -myStr @"
Please select your current EEI Version from below (must match your current EEI Server Version):

	1 - 1.6.1716.0
	2 - 1.6.1738.0
	3 - 1.6.1755.0
	4 - 1.6.1764.0
	
	Q - Not Listed - Exit

"@
	[string] $eeiVerSelect = Read-Host "Enter a selection"
	Switch ($eeiVerSelect.ToUpper()) {
		'1'{
			$eeiSetVer = "1.6.1716.0"
		}'2'{
			$eeiSetVer = "1.6.1738.0"
		}'3'{
			$eeiSetVer = "1.6.1755.0"
		}'4'{
			$eeiSetVer = "1.6.1764.0"
		}'Q'{
			myLogger -myStr "Selected to Quit - $($eeiVerSelect)"
			exit
		}
	}
	myLogger -myStr "  - Selected item $($eeiVerSelect.ToUpper()) - $($eeiSetVer)"
	return $eeiSetVer
}


Write-Host "`r`n`r`nPlease supply the follwoing ""EEI Connection"" info:"
#$EsmcHost = "10.0.0.118"
$EsmcHost = Read-Host "  EEI Server Hostname/IP"
#$Esmcuser = "Demo\jradmin"
$Esmcuser = Read-Host "  Username or Domain\Username"
#$EsmcPass = "Eset.nod32"
$EsmcPass = Read-Host "  Password" -AsSecureString

If ($Esmcuser.contains("\")) {
	$EsmcIsDomainUser = $True
}else{
	$EsmcIsDomainUser = $False
}
$token = ""
$response = ""

#Get Server Version
$eeiSetVer = getSvrVer
If ($eeiSetVer -eq $null) {$eeiSetVer = promptSvrVer}

myLogger -myStr "  - Server Version set to: $($eeiSetVer)"

myLogger -myStr @"
`r`n`r`nWhich Rule Profile would you like  to set?

	A - SOC Profile (All Possible Detections)
	B - Security Focused IT (Warning and Threat level detections)
	C - IT Administrator (Threat level and highly probably threats only)
	
	Q - Quit

"@
[string] $eeiRuleProfSelect = Read-Host "Enter a selection"
Switch ($eeiRuleProfSelect.ToUpper()) {
	'A'{
		$eeiSetRProf = "SOC_ALL"
	}'B'{
		$eeiSetRProf = "SecIT_WarnAndThreat"
	}'C'{
		$eeiSetRProf = "IT_Threat"
	}'Q'{
		myLogger -myStr "Selected to Quit - $($eeiRuleProfSelect)"
		exit
	}
}
myLogger -myStr "  - Selected Rule Profile $($eeiRuleProfSelect.ToUpper()) - $($eeiSetRProf)`r`n  - Using: ""$($PSScriptRoot)\RuleProfiles\$($eeiSetVer)\$($eeiSetRProf).csv"""

If (Test-Path -Path "$($PSScriptRoot)\RuleProfiles\$($eeiSetVer)\$($eeiSetRProf).csv" -Type Leaf) {
	$myCsv = Import-Csv -Path "$($PSScriptRoot)\RuleProfiles\$($eeiSetVer)\$($eeiSetRProf).csv"
}else{
	myLogger -myStr "EEI version $($eeiSetVer) may not be supported or .csv files are missing from script." -warnLvl "Threat"
	Exit
}






#Put blank lines to allow progress bar to not cover data on screen.
Write-Host "`r`n"






#create Hash Table with login credentials
$global:LoginReq = @{}
$global:LoginReq.username     = $Esmcuser
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($EsmcPass)
$global:LoginReq.password     = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
$BSTR = $Null
$global:LoginReq.domain       = $EsmcIsDomainUser


<#check if domain, if true verify username has correct formatting.  Give error and exit if not correct
If ($global:LoginReq.domain -eq $True) {
    If (-not $global:LoginReq.username.Contains("\")) {
        Write-Error -Message "Must be a domain user.  Username $($global:LoginReq.username) does not contain proper formatting of ""domain\username""."
        exit
    }
}
#>
$token = authenticate($global:LoginReq)
if ($verbose) {
	myLogger -myStr  "Token: $($token)"
}

$svrInfo = getSvrVer

#create Hash Table to be used in query
$query = @{}
$query.'$count' = 1
$query.'$top' = 0
#get the total count of rules on the server
$totRulesOnSvr = ((getRules($query)).content | ConvertFrom-Json).count
$query = @{}
$query.'$top' = $totRulesOnSvr #specify how many rules to grab from server.
$rulesFull = getRules($query)


if ($verbose) {
    myLogger -myStr  "----------------rulesFull------------------"
    $rulesFull
    myLogger -myStr  "----------------rulesFull Content------------------"
    $rulesFull.content
}
$summRulesBefore = "`r`n----------------Summary of Rules Before------------------"
# put all rules into a single object named '$rules'
$rules = ($rulesFull.content | ConvertFrom-Json).value
$summRulesBefore += "`r`nServer total rule count: $($rules.count)"
$summRulesBefore += "`r`n    Count of enabled before: $(($rules | Where-Object {$_.enabled -eq $True}).count)"
$summRulesBefore += "`r`n    Count of disabled before: $(($rules | Where-Object {$_.enabled -eq $False}).count)"
$summRulesBefore += "`r`nExport CSV or rules before changes: $($global:myLogFldr)\$($timeStamp)_RulesTable_Before.csv"
$rules | ConvertTo-Csv | Out-File -FilePath "$($global:myLogFldr)\$($timeStamp)_RulesTable_Before.csv"


<#
$singleRule = getRule(19)
#$singleRule
(($singleRule.content | ConvertFrom-Json).Rule).name
(($singleRule.content | ConvertFrom-Json).Rule).enabled
(($singleRule.content | ConvertFrom-Json).Rule).id

$query = @{}
$query.enabled = 0
$query = ($query | ConvertTo-Json)
enableDisableRule(19, $query)



$singleRule = getRule(19)
#$singleRule
(($singleRule.content | ConvertFrom-Json).Rule).name
(($singleRule.content | ConvertFrom-Json).Rule).enabled
(($singleRule.content | ConvertFrom-Json).Rule).id
#>


myLogger -myStr  "ACTION... PRIOR_STATE : ID : RULE_NAME"
$countTotal = 0
$countEnabled = 0
$countDisabled = 0
ForEach ($rule in $rules) {
	$countTotal++
	#Write-Progress -Id 0 "Step $rule"
	#Write-Progress -Activity "Updating Rules" -Status "$(($countTotal/$($rules.count))*100)% Complete"
	Write-Progress -Activity "Updating Rules" -Status "Percent complete: $([Math]::Round(($countTotal/$($rules.count))*100,2))%"
	#myLogger -myStr  "Working on... $($rule.id) : $($rule.name)"
	#myLogger -myStr  "$rule"
	If ("true" -eq ($myCsv -match [regex]::escape($rule.name)).enabled -AND $rule.enabled -ne $True){
		myLogger -myStr  "  + Enabling... $($rule.enabled) : $($rule.id) : $($rule.name)"
		$query = @{}
		$query.enabled = 1
		$temp = enableDisableRule($rule.id, $query)
		$countEnabled++
	}ElseIf ("false" -eq ($myCsv -match [regex]::escape($rule.name)).enabled -AND $rule.enabled -ne $False) {
		myLogger -myStr  "  - Disabling... $($rule.enabled) : $($rule.id) : $($rule.name)"
		$query = @{}
		$query.enabled = 0
		$temp = enableDisableRule($rule.id, $query)
		$countDisabled++
	}
	#ForEach ($ruleToEnable in ($myCsv | Where-Object {$_.name -eq $rule.name -and $_.enabled -eq "true"})) {
	#	myLogger -myStr  "Time to ENABLE rule $($rule.id) : $($rule.name)"
	#}
}

myLogger -myStr "$($summRulesBefore)"

myLogger -myStr  "`r`n----------------Summary of Changes------------------"
myLogger -myStr  "Count of rules enabled by this script: $($countEnabled)"
myLogger -myStr  "Count of rules disabled by this script: $($countDisabled)"

$query = @{}
$query.'$top' = $totRulesOnSvr #specify how many rules to grab from server.
$rulesFullAfter = getRules($query)
if ($verbose) {
    myLogger -myStr  "----------------rulesFull------------------"
    $rulesFullAfter
    myLogger -myStr  "----------------rulesFull Content------------------"
    $rulesFullAfter.content
}

# Get counts of all enabled/disabled rules after changes'
$rules = ($rulesFullAfter.content | ConvertFrom-Json).value
myLogger -myStr  "`n----------------Enabled/Disabled After------------------"
myLogger -myStr  "    Count of enabled after: $(($rules | Where-Object {$_.enabled -eq $True}).count)"
myLogger -myStr  "    Count of disabled after: $(($rules | Where-Object {$_.enabled -eq $False}).count)"
myLogger -myStr  "Export CSV or rules after changes: $($global:myLogFldr)\$($timeStamp)_RulesTable_After.csv"
$rules | ConvertTo-Csv | Out-File -FilePath "$($global:myLogFldr)\$($timeStamp)_RulesTable_After.csv"

myLogger -myStr "Log File Created: $($global:myLog)"

#blank line before ending
Write-Host "`r`n"
