# This is a script to get CyberArk users and their details
# (c) This is a modified version of the script taken from CyberArk
# Original script:
# NAME: Import a Platform or a Connection Component
# Original script AUTHOR: Yair Assa
# Modified script author: Dmitriy Reznikov
param
(
	[Parameter(Mandatory=$true,HelpMessage="Enter the PVWA URL in format https://put.your.vault.address.here/PasswordVault")]
	# for quick debug:
	#[Parameter(Mandatory=$false,HelpMessage="Enter the PVWA URL in format https://put.your.vault.address.here/PasswordVault")]
	[Alias("url")]
	[String]$PVWAURL="https://put.your.vault.address.here/PasswordVault"
)

# Global URLS
# -----------
$URL_PVWAWebServices = $PVWAURL+"/WebServices"
$URL_PVWAAPI = $PVWAURL+"/api"

# URL Methods
# -----------
$URL_CyberArkLogon = $URL_PVWAAPI+"/auth/Cyberark/Logon"
$URL_CyberArkLogoff = $URL_PVWAAPI+"/auth/Logoff"
$URL_GetUsers = $URL_PVWAAPI+"/Users"
$URL_GetUserDetails = $URL_PVWAWebServices+"/PIMServices.svc/Users/"
$URL_GetUserDetailsV10 = $URL_PVWAAPI+"/Users/"


# Initialize Script Variables
# ---------------------------
# Save Global Logon Token
$g_LogonHeader = ""


#region Helper Functions
Function Invoke-Rest
{
	param ($Command, $URI, $Header, $Body, $ErrorAction="Continue")

	$restResponse = ""
	try{
		Write-Verbose "Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType ""application/json"" -Body $Body"
		$restResponse = Invoke-RestMethod -Uri $URI -Method $Command -Header $Header -ContentType "application/json" -Body $Body
	} catch {
		If($_.Exception.Response.StatusDescription -ne $null)
		{
			Write-Error $_.Exception.Response.StatusDescription -ErrorAction $ErrorAction
		}
		else
		{
			Write-Error "StatusCode: $_.Exception.Response.StatusCode.value__"
		}
		$restResponse = $null
	}
	Write-Verbose $restResponse
	return $restResponse
}

Function Invoke-Get
{
	param ($URI, $Header, $ErrorAction="Continue")

	$restResponse = ""
	try{
		Write-Verbose "Invoke-RestMethod -Uri $URI -Header $Header -ContentType ""application/json"" "
		$restResponse = Invoke-RestMethod -Uri $URI -Header $Header -ContentType "application/json"
	} catch {
		If($_.Exception.Response.StatusDescription -ne $null)
		{
			Write-Error $_.Exception.Response.StatusDescription -ErrorAction $ErrorAction
		}
		else
		{
			Write-Error "StatusCode: $_.Exception.Response.StatusCode.value__"
		}
		$restResponse = $null
	}
	Write-Verbose $restResponse
	return $restResponse
}

Function Get-LogonHeader
{
	param($Credentials)
	# Create the POST Body for the Logon
    # ----------------------------------
    $logonBody = @{ username=$Credentials.username.Replace('\','');password=$Credentials.GetNetworkCredential().password } | ConvertTo-Json
	write-Verbose $logonBody
    try{
	    # Logon
	    $logonToken = Invoke-Rest -Command Post -Uri $URL_CyberArkLogon -Body $logonBody
	    # Clear logon body
	    $logonBody = ""
	}
	catch
	{
        Write-Error "Failed to login"
		Write-Host -ForegroundColor Red $_.Exception.Response.StatusDescription
		$logonToken = ""
        exit
	}
    If ($logonToken -eq "")
    {
        Write-Host -ForegroundColor Red "Logon Token is Empty - Cannot login"
        exit
    }
	
    # Create a Logon Token Header (This will be used through out all the script)
    # ---------------------------
    $logonHeader =  New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $logonHeader.Add("Authorization", $logonToken)
	
	return $logonHeader
}

Function Login
{
	Write-Host "Loggin into the Vault"
    $caption = "Get Users"
	$msg = "Enter your User name and Password"; 
	$creds = $Host.UI.PromptForCredential($caption,$msg,"","")
	# For quick debug:
	# $secpasswd = ConvertTo-SecureString "password" -AsPlainText -Force
	# $username = "username"
	# $creds = New-Object System.Management.Automation.PSCredential ($username, $secpasswd)
	if ($creds -ne $null)
	{
		$g_LogonHeader = $(Get-LogonHeader -Credentials $creds)
		Write-Host "Got logon header"
	}
	else {
		Write-Error "Failed to get Credentials"
		exit
	}

    return $g_LogonHeader
}

Function GetUsers
{
	Write-Host "Get users"
    $restResult = $(Invoke-Get -Uri $URL_GetUsers -Header $g_LogonHeader)
	# exit
    if ($restResult -ne $null)
	{
		Write-Output "GetUsers finished succesfully"
		Write-Host $restResult
		return $restResult
	} else {
		Write-Error "No users found or you don't have permissions to see them"
	}
	return ""
}

# This is outdated function and doesn't display a lot of information
Function GetUserDetails
{
	param($user)
	Write-Host "Get $user user details"
    $userURL = $URL_GetUserDetails + $user
    $restResult = $(Invoke-Get -Uri $userURL -Header $g_LogonHeader)
    if ($restResult -ne $null)
	{
		Write-Output "Got user details:"
		Write-Host $restResult
		return $restResult
	} else {
		Write-Error "You don't have permissions to see details"
	}
	return ""
}

# This is a new API that we need to use
# Todo: improve it to allow searching and filtering
# 
Function GetUserDetailsV10
{
	param($user, $id)
	Write-Host "Get $user user details"
    $userURL = $URL_GetUserDetailsV10 + $id
    $restResult = $(Invoke-Get -Uri $userURL -Header $g_LogonHeader)
    if ($restResult -ne $null)
	{
		Write-Output "Got user details:"
		Write-Host $restResult
		Write-Host "authenticationMethod " $restResult.authenticationMethod
		Write-Host "unAuthorizedInterfaces " $restResult.unAuthorizedInterfaces
		Write-Host "vaultAuthorization " $restResult.vaultAuthorization
		return $restResult
	} else {
		Write-Error "You don't have permissions to see $user details"
	}
	return ""
}

Function Logoff
{
	Write-Host "Logoff"
	$restResult = Invoke-Rest -Uri $URL_CyberArkLogoff -Header $g_LogonHeader -Command "Post"
}

#endregion

#--------- SCRIPT BEGIN ------------

#Set TLS Protocol level
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#region [Validation]
# Check Powershell version
If($($PSVersionTable.PSVersion.Major) -le 2)
{
   Write-Error "This script requires Powershell version 3 or above"
   exit
}
#endregion

#Logon
$g_LogonHeader = $(Login)

# Get all users
$users = GetUsers

# Get all users details (old version), uncomment lines below, if required
# $allUsersDetailsClassic = @{}
# foreach($user in $users.Users) {
	# $allUsersDetailsClassic[$user.username] = GetUserDetails $user.username
# }

Write-Host "Get and display details of each user"
# Initialise hash table that will contain details of all our users
$allUsersDetailsV10 = @{}
# Go over all users that we got from previous command
foreach($user in $users.Users) {
	# For each user get user details and write it to the has table, using user ID as the key
	$allUsersDetailsV10[$user.id] = GetUserDetailsV10 $user.username $user.id
}

Write-Host "Display authentication method for each user"
# Loop over all ids in our hash table with all users details
foreach($id in $allUsersDetailsV10.Keys) {
	# Display user name and authentication methods
	Write-Host $allUsersDetailsV10[$id].username " " $allUsersDetailsV10[$id].authenticationMethod
	# Other available parameters can be found here:
	# https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/get-user-details-v10.htm
	# Check Result - column named "Parameter" reperesents available parameters
	# For example:
	# Write-Host $allUsersDetailsV10[$id].enabled
	# will show you if user is enabled or not
}

#Logoff
Logoff
