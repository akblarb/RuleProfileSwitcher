$verbose = $False

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



#[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
#[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Functions
<#
function sendRequest($Request) {
    $Response = $Null
    [ServerApi]::era_process_request($Request,[ref]$Response)
    return $Response | ConvertFrom-Json
}
#>
function authenticate ($authLoginReq) {
	myLogger -myStr "  - Connecting directly to EI Host $($global:EiHost) with Username $($Esmcuser)"
    $response = Invoke-WebRequest -Method PUT -Uri "https://$($global:EiHost)/api/v1/authenticate" -Body ($authLoginReq | ConvertTo-Json) -SkipCertificateCheck #this skip cert switch only works on v7 Powershell(possibly on v6)
	#clear out any credentials
	$authLoginReq = $Null
	$global:LoginReq = $Null
	if ($verbose) {
        myLogger -myStr  "resp06: $($response)"
    }
    If ($response.StatusCode -eq 200) {
        #return ($response.headers)
		#return $response
        return ($response.headers['X-Security-Token'])
    } Else {
        myLogger -myStr "Failed to authenticate.  Received HTTP Error: $($response.StatusCode)" -warnLvl "threat"
		#exit
    }
}

function authenticateRemCon ($authLoginReq) {
	myLogger -myStr " - Connecting to EI Remote Connection $($global:EiHost) with Username $($Esmcuser)"
	$url="https://$($global:EiHost)/Auth?token=$($EiRemConToken)"
	myLogger -myStr " - Connecting to URL: $($url)"
	myLogger -myStr " - Using cert located here: $($EiClientCert)"
	myLogger -myStr "$($EiClientCertX509.ToString())"
    #$resp00 = Invoke-WebRequest -Method GET -Uri $url -SessionVariable "global:seshGetAuthEi"  -Certificate (Get-PfxCertificate -FilePath $certName -NoPromptForPassword) -SkipCertificateCheck #this skip cert switch only works on v7 Powershell(possibly on v6)
	$resp00 = Invoke-WebRequest -Method GET -Uri $url -SessionVariable "global:seshGetAuthEi"  -Certificate $EiClientCertX509 -SkipCertificateCheck #this skip cert switch only works on v7 Powershell(possibly on v6)
	$response = Invoke-WebRequest -Method PUT -Uri "https://$($global:EiHost)/api/v1/authenticate" -websession $global:seshGetAuthEi -Body ($authLoginReq | ConvertTo-Json) -SkipCertificateCheck #this skip cert switch only works on v7 Powershell(possibly on v6)
	#clear out any credentials
	$authLoginReq = $Null
	$global:LoginReq = $Null
    If ($response.StatusCode -eq 200) {
        #return ($response.headers)
		#return $response
        return ($response.headers['X-Security-Token'])
    } Else {
        myLogger -myStr "Failed to authenticate.  Received HTTP Error: $($response.StatusCode)" -warnLvl "threat"
		#exit
    }
}

function authenticateEIC ($authLoginReq) {
    myLogger -myStr " - Connecting to EIC Host $($global:EiHost) with Username $($Esmcuser)"
    #Send Initial Auth
    $resp02 = Invoke-WebRequest -Method POST -Uri "https://identity.eset.com/api/login/pwd" -websession $global:seshGetAuthEi -Body ($authLoginReq | ConvertTo-Json) -Headers @{'Content-Type' = 'application/json '}-MaximumRedirection 0
    If ((($resp02.Content| ConvertFrom-Json).responseType) -eq 20) {
        #Begin 2FA challenge
        $tfaChallenge = @{}
        $tfaChallenge.code = (Read-Host "  Enter one time password")
        $tfaChallenge.returnUrl = $authLoginReq.returnUrl
        $tfaChallenge.isBackupCode = $false
        $tfaChallenge.rememberAuthentication = $false
        $resp02fa = Invoke-WebRequest -Method POST -Uri "https://identity.eset.com/api/login/tfa" -websession $global:seshGetAuthEi -Body ($tfaChallenge | ConvertTo-Json) -Headers @{'Content-Type' = 'application/json '}
    }
    
	$myError = $null
    $resp03 = Invoke-WebRequest -Method GET -Uri $callback -websession $global:seshGetAuthEi -MaximumRedirection 0 -SkipHttpErrorCheck -ErrorAction SilentlyContinue -ErrorVariable myError
	If (-Not ($myError.ErrorDetails.Message).StartsWith("The maximum redirection count has been exceeded.")){
		myLogger -myStr "An unexpected Error Occurred" -warnLvl "threat"
		myLogger -myStr "ErrorDetails.Message: $($myError.ErrorDetails.Message)" -warnLvl "threat"
		myLogger -myStr "Exception.HResult: $($myError.Exception.HResult)" -warnLvl "threat"
		$myError
		Break
	}
	
	$myError = $null
    $resp04 = Invoke-WebRequest -Method GET -Uri  $($resp03.Headers.'Location') -websession $global:seshGetAuthEi -MaximumRedirection 0 -SkipHttpErrorCheck -ErrorAction SilentlyContinue -ErrorVariable myError
	If (-Not ($myError.ErrorDetails.Message).StartsWith("The maximum redirection count has been exceeded.")){
		myLogger -myStr "An unexpected Error Occurred" -warnLvl "threat"
		myLogger -myStr "ErrorDetails.Message: $($myError.ErrorDetails.Message)" -warnLvl "threat"
		myLogger -myStr "Exception.HResult: $($myError.Exception.HResult)" -warnLvl "threat"
		$myError
		Break
	}


    $resp05 = Invoke-WebRequest -Method GET -Uri  $($resp04.Headers.'Location') -websession $global:seshGetAuthEi -MaximumRedirection 0 #"$resp04.Headers.'Location'" Will contain the correct regional server where EIC lives US1, EU1, etc

    $urlRegion = $resp04.Headers.'Location'.Split('?')[0] #pulls the speicific URL for a region where EIC server lives.  Like: https://us01.inspect.eset.com/
    myLogger -myStr "Changing from EIC Host $($global:EiHost) to Regional Server: $($urlRegion.split("/")[2])"
    $global:EiHost = $urlRegion.split("/")[2]
    myLogger -myStr "EIC Host is now: $($global:EiHost)"
    $loginCodeStr = ($resp03.Headers.'Location'.Split('&') | where {$_ -like "code=*"}).split('=')[1]
    $global:LoginCode = @{}
    $global:LoginCode.ott = $loginCodeStr
    $resp06 = Invoke-WebRequest -Method POST -Uri  "$($urlRegion)frontend/login" -websession $global:seshGetAuthEi -Body ($global:LoginCode | ConvertTo-Json) -MaximumRedirection 5
    if ($verbose) {
        myLogger -myStr  "resp06: $($resp06)"
    }
    
    #myLogger -myStr $resp06.StatusCode
    If ($resp06.StatusCode -eq 200) {
        #return ($response.headers)
		#return $response
        return @(($resp06.Headers['X-Security-Token']), ($resp06 | ConvertFrom-Json).ServerVersion)
    } Else {
        myLogger -myStr "Failed to authenticate EIC.  Received HTTP Error: $($resp06.StatusCode)" -warnLvl "threat"
		#exit
    }
}

function getRules ($reqQuery) {
	#$response = Invoke-WebRequest -Method GET -Uri "https://$($global:EiHost)/api/v1/rules" -Body $reqQuery -Headers @{'Authorization' = 'Bearer '+$global:token}  -SkipCertificateCheck #this skip cert switch only works on v7 Powershell(possibly on v6)
    $response = Invoke-WebRequest -Method GET -Uri "https://$($global:EiHost)/api/v1/rules" -Body $reqQuery -Headers @{'Authorization' = 'Bearer '+$global:token} -websession $global:seshGetAuthEi  -SkipCertificateCheck #this skip cert switch only works on v7 Powershell(possibly on v6)
    If ($response.StatusCode -eq 200) {
        #return ($response.headers)
        return $response
    } Else {
        myLogger -myStr "Failed to get rules.  Received HTTP Error: $($response.StatusCode)" -warnLvl "threat"
		break
    }
}
#'{"pageSize":5000,"forceRefresh":false,"groupId":1,"localFilters":{"filterTree":{"AND":[{"status":{"EQ":0}},{"eventsFilter":{"EQ":0}}]},"subgroups":false},"sortOrders":[{"column":"name","ascend":true}],"requiredFields":["id","severity","enabled","ruleFamilyId","hasActiveActions","accessGroupId","accessGroupPath","isInternal","name","author","valid","changeDate","hitCount","targets","accessGroup","category"]}'
function getRulesEIC ($reqQuery) {
	#$response = Invoke-WebRequest -Method GET -Uri "https://$($global:EiHost)/api/v1/rules" -Body $reqQuery -Headers @{'Authorization' = 'Bearer '+$global:token}  -SkipCertificateCheck #this skip cert switch only works on v7 Powershell(possibly on v6)
    $response = Invoke-WebRequest -Method GET -Uri "https://$($global:EiHost)/frontend/rules/0" -Body $reqQuery -Headers @{'Authorization' = 'Bearer '+$global:token} -websession $global:seshGetAuthEi  -SkipCertificateCheck #this skip cert switch only works on v7 Powershell(possibly on v6)
    If ($response.StatusCode -eq 200) {
        #return ($response.headers)
        return $response
    } Else {
        myLogger -myStr "Failed to get rules.  Received HTTP Error: $($response.StatusCode)" -warnLvl "threat"
		break
    }
}


function getRule ($id) {
	    $response = Invoke-WebRequest -Method GET -Uri "https://$($global:EiHost)/api/v1/rules/$id" -Body $reqQuery -Headers @{'Authorization' = 'Bearer '+$global:token}-websession $global:seshGetAuthEi  -SkipCertificateCheck #this skip cert switch only works on v7 Powershell(possibly on v6)
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
	    $response = Invoke-WebRequest -Method PATCH -Uri "https://$($global:EiHost)/api/v1/rules/$($reqQuery[0])" -Body ($reqQuery[1] | ConvertTo-Json) -Headers @{'Authorization' = 'Bearer '+$global:token}-websession $global:seshGetAuthEi  -SkipCertificateCheck #this skip cert switch only works on v7 Powershell(possibly on v6)
		#response 204 = Success
    If ($response.StatusCode -eq 204) {
        #return ($response.headers)
        return $response
    } Else {
        return "Failed to Enable/Disable rule.  Received HTTP Error: $($response.StatusCode)"
    }
}

# Allows to bulk enable or disable a list of rules all at once.  Can only bulk enable or buld disable one at a time.  Cannot bulk disable and enable at same time.
# reqQuery[0] = "enable" or "disable"
# reqQuery[1] = JSON String to Post
function cloudEnableDisableRules ($reqQuery) {
	#myLogger -myStr  "`r`n`r`n$($reqQuery[1])`r`n`r`n"
	Try {
		$response = Invoke-WebRequest -Method POST -Uri "https://$($global:EiHost)/frontend/rules/$($reqQuery[0])" -Body $reqQuery[1] -Headers @{'Authorization' = 'Bearer '+$global:token}-websession $global:seshGetAuthEi  -SkipCertificateCheck #this skip cert switch only works on v7 Powershell(possibly on v6)
	}Catch [System.Net.Http.HttpRequestException]{
		$curError = $error[0]
		myLogger -myStr $($curError.ErrorDetails.Message) -warnLvl threat warn
		myLogger -myStr $($curError.Exception.GetType().FullName) -warnLvl threat
		myLogger -myStr $($error[0].InvocationInfo.PositionMessage) -warnLvl threat
		$curError = $null
	}Catch{
		$curError = $error[0]
		myLogger -myStr $($curError.ErrorDetails.Message) -warnLvl threat
		myLogger -myStr $($curError.Exception.GetType().FullName) -warnLvl warn
		myLogger -myStr $($error[0].InvocationInfo.PositionMessage) -warnLvl threat
		$curError = $null
	}
    If ($response.StatusCode -eq 200) {
        #return ($response.headers)
        return $response
    } Else {
        return "Failed to Enable/Disable rule.  Received HTTP Error: $($response.StatusCode)`r`n`r`n$($reqQuery[1])"
    }
}


#function to get server version from "serverinfo.js"
function getSvrVer () {
	myLogger -myStr "`r`nGrabbing EEI Server Version from https://$($global:EiHost)/serverinfo.js"
	$response = Invoke-WebRequest -Method GET -Uri "https://$($global:EiHost)/serverinfo.js"-websession $global:seshGetAuthEi  -SkipCertificateCheck #this skip cert switch only works on v7 Powershell(possibly on v6)
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
	5 - 1.6.1766.0
	6 - 1.7.1978.0
	7 - 1.7.1991.0
	8 - 1.11.2872.0
	
	Q - Not Listed - Exit

"@
	[string] $eeiVerSelect = Read-Host "Enter a selection"
	Switch ($eeiVerSelect.ToUpper()) {
		'1'{
			$global:eeiSetVer = "1.6.1716.0"
		}'2'{
			$global:eeiSetVer = "1.6.1738.0"
		}'3'{
			$global:eeiSetVer = "1.6.1755.0"
		}'4'{
			$global:eeiSetVer = "1.6.1764.0"
		}'5'{
			$global:eeiSetVer = "1.6.1766.0"
		}'6'{
			$global:eeiSetVer = "1.7.1978.0"
		}'7'{
			$global:eeiSetVer = "1.7.1991.0"
		}'8'{
			$global:eeiSetVer = "1.11.2872.0"
		}'Q'{
			myLogger -myStr "Selected to Quit - $($eeiVerSelect)"
			exit
		}
	}
	myLogger -myStr "  - Selected item $($eeiVerSelect.ToUpper()) - $($global:eeiSetVer)"
	return $global:eeiSetVer
}


Write-Host "`r`n`r`nPlease supply the follwoing ""EEI Connection"" info:"
#$global:EiHost = "10.0.0.118"
$global:EiHostType = "NotSet" #Can be RemCon,OnPrem,Cloud
$global:EiHost = Read-Host "  Inspect Server Hostname/IP"
If ($global:EiHost -eq "edr-remote.eset.com") {
	$global:EiHostType = "RemCon"
	$EiRemConToken = Read-Host "  Provide token for Remote Connection"
	$EiClientCert = Read-Host "  Provide path to .pfx or thumbprint in personal store"
	
	#if Client Cert is a file path, then 
	if ($EiClientCert -clike "?:\*.pfx") {
		$EiClientCertX509 = (Get-PfxCertificate -FilePath $EiClientCert -NoPromptForPassword)
	} Else {
		$EiClientCertX509 = (Get-ChildItem -Path Cert:\CurrentUser\My\$($EiClientCert.ToUpper()))
	}
}

#$Esmcuser = "demo\jradmin"
$Esmcuser = Read-Host "  Username or Domain\Username"
#$EsmcPass = (ConvertTo-SecureString -String "password" -AsPlainText -Force)
$EsmcPass = Read-Host "  Password" -AsSecureString

If ($Esmcuser.contains("\")) {
	$EsmcIsDomainUser = $True
}else{
	$EsmcIsDomainUser = $False
}
$global:token = ""
$response = ""

<#check if domain, if true verify username has correct formatting.  Give error and exit if not correct
If ($global:LoginReq.domain -eq $True) {
    If (-not $global:LoginReq.username.Contains("\")) {
        Write-Error -Message "Must be a domain user.  Username $($global:LoginReq.username) does not contain proper formatting of ""domain\username""."
        exit
    }
}
#>
$global:authCounter = 0
Function Check-EiTypeAndLogon () {
	##### Perform logon to either OnPrem or Cloud
	$global:lastAuthTime = Get-Date
	If ($global:authCounter -eq 0) {
		myLogger -myStr "Authentication Time: $($global:lastAuthTime)"
	}Else{
		myLogger -myStr " - Reauth Time: $($global:lastAuthTime)"
	}
	If ($global:EiHost -eq "inspect.eset.com") {
		If ($global:authCounter -eq 0) {
			$global:EiHostType = "Cloud"
			myLogger -myStr "Connection type: EI Cloud"
			##### Get some info about server before login
			#Get Server Version
			#$global:eeiSetVer = getSvrVer
			#If ($global:eeiSetVer -eq $null) {$global:eeiSetVer = promptSvrVer}
			#myLogger -myStr " - Server Version set to: $($global:eeiSetVer)"
		}
		#null out web session variable
		$global:seshGetAuthEi = $null
		#set initial items for EICAuth
		$myError = $null
		$resp00 = Invoke-WebRequest -Method GET -Uri "https://inspect.eset.com" -SessionVariable "global:seshGetAuthEi" -MaximumRedirection 0 -SkipHttpErrorCheck -ErrorAction SilentlyContinue -ErrorVariable myError
		If (-Not ($myError.ErrorDetails.Message).StartsWith("The maximum redirection count has been exceeded.")){
			myLogger -myStr "An unexpected Error Occurred" -warnLvl "threat"
			myLogger -myStr "ErrorDetails.Message: $($myError.ErrorDetails.Message)" -warnLvl "threat"
			myLogger -myStr "Exception.HResult: $($myError.Exception.HResult)" -warnLvl "threat"
			$myError
			Break
		}
		
		$callback = ($resp00.Headers.'Location').Replace('/core/connect/authorize?', '/connect/authorize/callback?')
		$resp01 = Invoke-WebRequest -Method GET -Uri $($resp00.Headers.'Location') -websession $global:seshGetAuthEi -MaximumRedirection 5
		#create Hash Table with EIC login credentials
		$global:LoginReq = @{}
		$global:LoginReq.email     = $Esmcuser
		$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($EsmcPass)
		$global:LoginReq.password     = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
		$global:LoginReq.returnUrl = $callback.Replace('https://identity.eset.com', '')
		$BSTR = $Null
		#Authenticate
		$global:token, $global:eeiSetVer = authenticateEIC($global:LoginReq)
		myLogger -myStr " - Server Version set to: $($global:eeiSetVer)"
	} elseIf ($global:EiHost -eq "edr-remote.eset.com") {
		$global:EiHostType = "RemCon"
		myLogger -myStr "Connection type: Remote Connector"
		myLogger -myStr " - Might need to add in a 'getSvrVer' call here."
		#null out web session variable
		#$global:seshGetAuthEi = $null
		#create Hash Table with login credentials
		$global:LoginReq = @{}
		$global:LoginReq.username     = $Esmcuser
		$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($EsmcPass)
		$global:LoginReq.password     = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
		$BSTR = $Null
		$global:LoginReq.domain       = $EsmcIsDomainUser
		#Authenticate
		$global:token = authenticateRemCon($global:LoginReq)
	} else {
		If ($global:authCounter -eq 0) {
			$global:EiHostType = "OnPrem"
			myLogger -myStr "Connection type: Direct OnPrem Web Console"
			##### Get some info about server before login
			#Get Server Version
			$global:eeiSetVer = getSvrVer
			#If ($global:eeiSetVer -eq $null) {$global:eeiSetVer = promptSvrVer}
			myLogger -myStr "  - Server Version set to: $($global:eeiSetVer)"
		}
		#null out web session variable
		$seshGetAuthEi = $null
		#create Hash Table with login credentials
		$global:LoginReq = @{}
		$global:LoginReq.username     = $Esmcuser
		$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($EsmcPass)
		$global:LoginReq.password     = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
		$BSTR = $Null
		$global:LoginReq.domain       = $EsmcIsDomainUser
		#Authenticate
		$global:token = authenticate($global:LoginReq)
	}
	$global:authCounter += 1
	if ($verbose) {
		myLogger -myStr  "Token: $($global:token)"
	}
}
Check-EiTypeAndLogon

#Get Server Version
#$global:eeiSetVer = getSvrVer
If ($global:eeiSetVer -eq $null) {$global:eeiSetVer = promptSvrVer}


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
myLogger -myStr "  - Selected Rule Profile $($eeiRuleProfSelect.ToUpper()) - $($eeiSetRProf)`r`n  - Using: ""$($PSScriptRoot)\RuleProfiles\$($global:eeiSetVer)\$($eeiSetRProf).csv"""

If (Test-Path -Path "$($PSScriptRoot)\RuleProfiles\$($global:eeiSetVer)\$($eeiSetRProf).csv" -Type Leaf) {
	$myCsv = Import-Csv -Path "$($PSScriptRoot)\RuleProfiles\$($global:eeiSetVer)\$($eeiSetRProf).csv"
}else{
	myLogger -myStr "EEI version $($global:eeiSetVer) may not be supported or .csv files are missing from script." -warnLvl "Threat"
	Exit
}






#Put blank lines to allow progress bar to not cover data on screen.
Write-Host "`r`n"









myLogger -myStr " ---- Current EI Type: $($EiHostType) ----"
If ($global:EiHostType -eq "Cloud"){
	$query = '{"pageSize":5000,"forceRefresh":false,"groupId":1,"localFilters":{"filterTree":{"AND":[{"status":{"EQ":0}},{"eventsFilter":{"EQ":0}}]},"subgroups":false},"sortOrders":[{"column":"name","ascend":true}],"requiredFields":["id","severity","enabled","ruleFamilyId","hasActiveActions","accessGroupId","accessGroupPath","isInternal","name","author","valid","changeDate","hitCount","targets","accessGroup","category"]}'
	$rulesFull = getRulesEIC($query)
	myLogger -myStr " ----------- RulesFullCloud ------------"
	#myLogger -myStr $rulesFull
}Else{
	#create Hash Table to be used in query
	$query = @{}
	$query.'$count' = 1
	$query.'$top' = 99999
	#get the total count of rules on the server
	$totRulesOnSvr = ((getRules($query)).content | ConvertFrom-Json).count
	$query = @{}
	$query.'$top' = $totRulesOnSvr #specify how many rules to grab from server.
	$rulesFull = getRules($query)

}


if ($verbose) {
    myLogger -myStr  "----------------rulesFull------------------"
    $rulesFull
    myLogger -myStr  "----------------rulesFull Content------------------"
    $rulesFull.content
}
$summRulesBefore = "`r`n----------------Summary of Rules Before------------------"
# put all rules into a single object named '$rules'
If ($global:EiHostType -eq "Cloud"){
	$rules = ($rulesFull | ConvertFrom-Json).entities
}Else{
	$rules = ($rulesFull.content | ConvertFrom-Json).value
}

Start-Sleep -Seconds 2
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
#$listToEnable = @()
#$listToDisable = @()
ForEach ($rule in $rules) {
	$countTotal++
	#Write-Progress -Id 0 "Step $rule"
	#Write-Progress -Activity "Updating Rules" -Status "$(($countTotal/$($rules.count))*100)% Complete"
	Write-Progress -Activity "Setting rule profile $($eeiSetRProf)" -Status "Percent complete: $([Math]::Round(($countTotal/$($rules.count))*100,2))%" -PercentComplete ([Math]::Round(($countTotal/$($rules.count))*100,2))
	#myLogger -myStr  "Working on... $($rule.id) : $($rule.name)"
	#myLogger -myStr  "$rule"
	# if ((rule in mycsv shows enabled) and (Rule on server is not enabled)) then build query to enable
	If ("true" -eq ($myCsv -match [regex]::escape($rule.name)).enabled -AND $rule.enabled -ne $True){
		myLogger -myStr  "  + Enabling... $($rule.enabled) : $($rule.id) : $($rule.name) :[1] $("true" -eq ($myCsv -match [regex]::escape($rule.name)).enabled) :[2] $($rule.enabled -ne $True)"
		
		If ($global:EiHostType -eq "Cloud"){
			$query = '{"groupId":1,"localFilters":{"filterTree":{"AND":[{"status":{"EQ":0}},{"eventsFilter":{"EQ":0}}]},"subgroups":false},"selection":[{"groupColumn":"","groupValue":"","column":"id","uniqueIds":['+ $($rule.id) +'],"selectAll":false}]}'
			$temp = cloudEnableDisableRules("enable", $query)
			#$listToEnable += $rule.id
			#myLogger -myStr  "  + To be enabled... $($rule.enabled) : $($rule.id) : $($rule.name) :[1] $("true" -eq ($myCsv -match [regex]::escape($rule.name)).enabled) :[2] $($rule.enabled -ne $True)"
			$countEnabled++
			##Forced Limit##If ($countEnabled -ge 5) {Write-Output "Hit forced limit.  Exiting script.";Break}
		}Else{
			$query = @{}
			$query.enabled = 1
			$temp = enableDisableRule($rule.id, $query)
			#$listToEnable += $rule.id
			#myLogger -myStr  "  + To be enabled... $($rule.enabled) : $($rule.id) : $($rule.name) :[1] $("true" -eq ($myCsv -match [regex]::escape($rule.name)).enabled) :[2] $($rule.enabled -ne $True)"
			$countEnabled++
			##Forced Limit##If ($countEnabled -ge 5) {Write-Output "Hit forced limit.  Exiting script.";Break}
		}
	}ElseIf ("false" -eq ($myCsv -match [regex]::escape($rule.name)).enabled -AND $rule.enabled -ne $False) {
		myLogger -myStr  "  - Disabling... $($rule.enabled) : $($rule.id) : $($rule.name) :[1] $("true" -eq ($myCsv -match [regex]::escape($rule.name)).enabled) :[2] $($rule.enabled -ne $True)"
		If ($global:EiHostType -eq "Cloud"){
			$query = '{"groupId":1,"localFilters":{"filterTree":{"AND":[{"status":{"EQ":0}},{"eventsFilter":{"EQ":0}}]},"subgroups":false},"selection":[{"groupColumn":"","groupValue":"","column":"id","uniqueIds":['+ $($rule.id) +'],"selectAll":false}]}'
			$temp = cloudEnableDisableRules("disable", $query)
			#$listToEnable += $rule.id
			#myLogger -myStr  "  + To be enabled... $($rule.enabled) : $($rule.id) : $($rule.name) :[1] $("true" -eq ($myCsv -match [regex]::escape($rule.name)).enabled) :[2] $($rule.enabled -ne $True)"
			$countDisabled++
			##Forced Limit##If ($countEnabled -ge 5) {Write-Output "Hit forced limit.  Exiting script.";Break}
		}Else{
			$query = @{}
			$query.enabled = 0
			$temp = enableDisableRule($rule.id, $query)
			#$listToDisable += $rule.id
			$countDisabled++
		}
	}Else {
		myLogger -myStr  "  o Skipping... $($rule.enabled) : $($rule.id) : $($rule.name) :[1] $("true" -eq ($myCsv -match [regex]::escape($rule.name)).enabled) :[2] $($rule.enabled -ne $True)"
	}
	
	#ForEach ($ruleToEnable in ($myCsv | Where-Object {$_.name -eq $rule.name -and $_.enabled -eq "true"})) {
	#	myLogger -myStr  "Time to ENABLE rule $($rule.id) : $($rule.name)"
	#}
}
Write-Progress -Activity "Setting rule profile $($eeiSetRProf)" -Status "Percent complete: $([Math]::Round(($countTotal/$($rules.count))*100,2))%" -PercentComplete ([Math]::Round(($countTotal/$($rules.count))*100,2)) -Completed

<# Bulk enabling fails at and only enables 235 max or 300 max.  Its always random and not very reliable.  Its likley due to sending additional enable request with not enough server time to finish processing prior request.
$frst = 0;$last = 2;$inc = 3;
	$frst += $inc;
	$last += $inc;
	$myArr[$frst..$last];
	"`r`n $($myArr.count - $last) remaining"
If ($listToEnable.count -gt 0) {
	$frstEnable = 0
	$lastEnable = 99
	$incEnable = 100
	myLogger -myStr  "  + Bulk Enabling $($listToEnable.count) Rules"
	$remainEnable = $listToEnable.count
	for ($totEnabled = 0; $totEnabled -le ($listToEnable.count -1); $totEnabled += $incEnable) {
		myLogger -myStr  "  ! enabling $($frstEnable) to $($lastEnable)"
		$rEnable =  bulkEnableDisableRules("enable" , $('{"groupId":1,"localFilters":{"filterTree":{"AND":[{"status":{"EQ":0}},{"eventsFilter":{"EQ":0}}]},"subgroups":false},"selection":[{"groupColumn":"","groupValue":"","column":"id","uniqueIds":['+ $($listToEnable[$frstEnable..$lastEnable] -join ",") +'],"selectAll":false}]}'))
		#$rEnable.content
		$frstEnable += $incEnable
		$lastEnable += $incEnable
		#$remainEnable = ($listToEnable.count - $lastEnable)
	}
}
If ($listToDisable.count -gt 0) {
	myLogger -myStr  "  + Bulk Disabling $($listToDisable.count) Rules"
	$rDisable = bulkEnableDisableRules("disable", $('{"groupId":1,"localFilters":{"filterTree":{"AND":[{"status":{"EQ":0}},{"eventsFilter":{"EQ":0}}]},"subgroups":false},"selection":[{"groupColumn":"","groupValue":"","column":"id","uniqueIds":['+ $($listToDisable -join ",") +'],"selectAll":false}]}'))
	#$rDisable.content
}

#>
myLogger -myStr "$($summRulesBefore)"

myLogger -myStr  "`r`n----------------Summary of Changes------------------"
myLogger -myStr  "Count of rules enabled by this script: $($countEnabled)"
myLogger -myStr  "Count of rules disabled by this script: $($countDisabled)"


myLogger -myStr " ---- Current EI Type at end: $($EiHostType) ----"
If ($global:EiHostType -eq "Cloud"){
	$query = '{"pageSize":5000,"forceRefresh":false,"groupId":1,"localFilters":{"filterTree":{"AND":[{"status":{"EQ":0}},{"eventsFilter":{"EQ":0}}]},"subgroups":false},"sortOrders":[{"column":"name","ascend":true}],"requiredFields":["id","severity","enabled","ruleFamilyId","hasActiveActions","accessGroupId","accessGroupPath","isInternal","name","author","valid","changeDate","hitCount","targets","accessGroup","category"]}'
	$rulesFullAfter = getRulesEIC($query)
}Else{
	$query = @{}
	$query.'$top' = $totRulesOnSvr #specify how many rules to grab from server.
	$rulesFullAfter = getRules($query)
}
if ($verbose) {
    myLogger -myStr  "----------------rulesFull------------------"
    $rulesFullAfter
    myLogger -myStr  "----------------rulesFull Content------------------"
    $rulesFullAfter.content
}

# Get counts of all enabled/disabled rules after changes'
If ($global:EiHostType -eq "Cloud"){
	$rules = ($rulesFullAfter | ConvertFrom-Json).entities
}Else{
	$rules = ($rulesFullAfter.content | ConvertFrom-Json).value
}
myLogger -myStr  "`n----------------Enabled/Disabled After------------------"
myLogger -myStr  "    Count of enabled after: $(($rules | Where-Object {$_.enabled -eq $True}).count)"
myLogger -myStr  "    Count of disabled after: $(($rules | Where-Object {$_.enabled -eq $False}).count)"
myLogger -myStr  "Export CSV or rules after changes: $($global:myLogFldr)\$($timeStamp)_RulesTable_After.csv"
$rules | ConvertTo-Csv | Out-File -FilePath "$($global:myLogFldr)\$($timeStamp)_RulesTable_After.csv"

myLogger -myStr "Log File Created: $($global:myLog)"

#blank line before ending
Write-Host "`r`n"
