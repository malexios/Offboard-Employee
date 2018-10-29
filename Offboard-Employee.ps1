## User Offboarding Tool
##
## Author: Michael Alexios
## 8/13/2018

## Description
# Disables a user in AD and O365 in a hybrid environment
# Disables AD account
# Move to 'Disabled Users' OU
# Change AD password
# Remove from groups
# Remove manager
# Disable OWA, ActiveSync
# Hide from address book
# Add comment to description
# Forward email
# Partial wipe mobile devices
# add user to litigation hold


## Requirements
# Powershell v4
# Powershell Active Directory Module
# Microsoft Online Services Sign-in Assistant / Windows Azure Active Directory Module
# Multi-Factor authentication for O365 module (Exchange Online Remote PowerShell Module) installed for the user running the script. 
# See: https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps


Import-Module ActiveDirectory
Import-Module -Name "C:\Program Files\Microsoft Azure AD Sync\Bin\ADSync"

# for password generator
Add-Type -AssemblyName System.Web

$LogPath = "C:\Scripts\logs\Offboard-Employee\Offboard-Employee_" + (Get-Date -Format MMddyy_hhmm) + ".log"

function Get-User {
    $ADuser = $null
    $EntryCount = 0
    do {
        if ($EntryCount -lt 4) {
            $UserName = Read-Host 'Enter username to disable'
            try {$ADUser = Get-ADuser -Identity $UserName -properties * -ErrorAction Continue}
            catch {
                Write-Host "That user is not found in Active Directory." -foregroundcolor yellow
                Write-Host "Make sure you are using the User Name (SamAccountName.)" -foregroundcolor yellow
                $EntryCount ++
            }
        } else {Write-Host "Too many tries!" -foregroundcolor red;pause;exit}
    } while (!$ADuser)
    return $ADUser
} # End Get-User

function Disable-User ($ADUser,$WONumber) {
    $Forward = Read-Host "Do you want to forward email sent to this user? (Y/N)"
    if ($Forward -eq 'y') {Set-Forwarding $ADUser}
    Write-Host "Disabling AD account..."
    $ADUser | Disable-ADAccount
    Write-Host "Changing password..."
    Set-Password $ADUser
    Write-Host "Removing manager..."
    $ADUser | Set-ADUser -manager $null
    Write-Host "Removing from groups..."
    Remove-UserFromGroups $ADUser
    Write-Host "Hiding from GAL..."
    $ADUser | Set-ADUser -Replace @{msExchHideFromAddressLists=$true}
    Write-Host "Disabling ActiveSync and OWA..."
    Set-CASMailbox -identity $ADUser.UserPrincipalName -popenabled:$false -imapenabled:$false -OWAEnabled:$false -OWAforDevicesEnabled $false -ActiveSyncEnabled:$false -MapiEnabled:$false
    Write-Host "Changing AD description..."
    $NewDescription = (get-aduser $ADUser.SamAccountName -Properties * | select *).description + " - DISABLED PER WO" + $WONumber + " - " + $env:username + " " + (Get-Date -Format MM/dd/yy)
    Set-ADUser -Identity $ADUser.SamAccountName -Description $NewDescription
    Write-Host "Blocking and wiping email from mobile devices..."
    Wipe-MobileDevices $ADUser
    Write-Host "Setting litigation hold..."
    Set-Mailbox $ADUser.UserPrincipalName -LitigationHoldEnabled $true
    # do this last
    Write-Host "Moving to Disabled Users OU..."
    $ADUser | Move-ADObject -TargetPath "OU=Disabled Users,DC=gablesnet,DC=com"
} # End Disable-User

function Wipe-MobileDevices ($ADUser){
    Write-Host "Checking" $ADUser.name "for connected devices..."
    try {$Devices = Get-MobileDevice -mailbox $ADUser.name | select *} catch{}
    if ($Devices) {
        Write-Host "Found connected device." -ForegroundColor Yellow
        foreach ($Device in $Devices) {
            if ($device.DeviceAccessState -ne "Blocked") {
                Write-Host "Blocking devices for" $ADUser.name -foregroundcolor yellow
                $DeviceType = $Device.DeviceType
                $DeviceID = $Device.DeviceID
                $DeviceUserAgent = $Device.DeviceUserAgent
                $DeviceIdentity = $Device.identity
                # Block and wipe device
                Block-Device $ADUser $DeviceType $DeviceUserAgent $DeviceID $DeviceIdentity
                $DeviceObject | ft
            } else {Write-Host "Device ID" $Device.DeviceID "is already blocked." -ForegroundColor Yellow}
        }
    }
} #  end Wipe-MobileDevices

function Block-Device ($ADUser,$DeviceType,$DeviceUserAgent,$DeviceID,$DeviceIdentity){
    # Block device
    # if you remove the device, you can't wipe it
    Write-Host "Blocking: " $DeviceType $DeviceUserAgent
    Set-CASMailbox -identity $ADUser.mail -EwsApplicationAccessPolicy EnforceBlockList -ActiveSyncBlockedDeviceIDs @{Add=$DeviceID}`
    -EwsBlockList @{Add=$DeviceID} -popenabled:$false -imapenabled:$false -OWAEnabled:$false -OWAforDevicesEnabled $false -ActiveSyncEnabled:$false
    # Wipe Device
    Write-Host "Wiping account information from" $DeviceIdentity
    get-mobiledevice -mailbox $ADUser.mail |  Clear-MobileDevice -AccountOnly -confirm:$false -NotificationEmailAddresses malexios@gables.com
}

function Set-Password ($ADUser) {
    # Generates a random 10 character password with four lowercase, two uppercase, two numbers and two symbols.
    # This does write the password to the log. Comment out the 'Write-Host' line to prevent this.
    $Password = $null
    $Uppercase = $null
    $Lowercase = $null
    $Symbols = $null
    $Numbers = $null

    For ($a=65;$a -le 90;$a++) {$Uppercase+=,[char][byte]$a}
    For ($a=97;$a -le 122;$a++) {$Lowercase+=,[char][byte]$a}
    For ($a=33;$a -le 47;$a++) {$Symbols+=,[char][byte]$a}
    $Numbers = @(1,2,3,4,5,6,7,8,9,0)

    $Password = ($Lowercase | get-random -count 4) -join ''
    $Password += ($Uppercase | get-random -count 2) -join ''
    $Password += ($Symbols | get-random -count 2) -join ''
    $Password += ($Numbers | get-random -count 2) -join ''
    # Randomizes the order of the password
    $password = ($password -split '' | Sort-Object {Get-Random}) -join ''

    Write-Host "New password:" $password
    $ADUser | Set-ADAccountPassword -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $Password -Force)
} # end Set-Password


function Remove-UserFromGroups ($ADUser) {
    $ADgroups = Get-ADPrincipalGroupMembership -Identity  $ADUser.SamAccountName | Where-Object {$_.Name -ne "Domain Users"}
    if ($ADGroups) {Remove-ADPrincipalGroupMembership -Identity  $ADUser.SamAccountName -MemberOf $ADgroups -Confirm:$false}
}

function Connect-O365MFA (){
    # Check for presense of this and give instruction to install module
    Import-Module $((Get-ChildItem -Path $($env:LOCALAPPDATA+"\Apps\2.0\") -Filter Microsoft.Exchange.Management.ExoPowershellModule.dll -Recurse ).FullName|?{$_ -notmatch "_none_"}|select -First 1)
    $EXOSession = New-ExoPSSession
    Import-PSSession $EXOSession
}

function Check-UserIsDisabled ($ADUser) {
    if (!(get-aduser -Identity $aduser.SamAccountName -Properties enabled | select enabled).enabled) {Write-Host "User is disabled" -ForegroundColor green} else {Write-Host "User is still enabled" -ForegroundColor red}
  #  if (!(Get-ADPrincipalGroupMembership -Identity  $ADUser.SamAccountName | where {$_.Name -ne "Domain Users"})) {Write-Host "User is not a member of any groups" -ForegroundColor green} else {Write-Host "User is still a member of groups" -ForegroundColor red}
    if (!(get-aduser -Identity $ADUser.SamAccountName -Properties manager | select manager).manager) {Write-Host "Manager is removed" -ForegroundColor green} else {Write-Host "Manager still exists" -ForegroundColor red}
    if ((get-aduser -Identity $ADUser.SamAccountName -Properties distinguishedname | select distinguishedname).distinguishedname -like '*Disabled Users*') {Write-Host "User is in Disabled Users OU" -ForegroundColor green} else {Write-Host "User is in the wrong OU" -ForegroundColor red}

    $MailboxActual = Get-CasMailbox $ADUser.UserPrincipalName
    if (!$MailboxActual.ActiveSyncEnabled){Write-Host "ActiveSync is disabled" -ForegroundColor green} else {Write-Host "ActiveSync is enabled" -ForegroundColor red}
    if (!$MailboxActual.OWAEnabled){Write-Host "OWA is disabled" -ForegroundColor green} else {Write-Host "OWA is enabled" -ForegroundColor red}
}

function Set-Forwarding ($ADUSer){
    # Creates a rule so that the new recipient sees that it is forwarded. Set-Mailbox -ForwardingAddress and -ForwardingsmtpAddress make it appear that the email was sent directly and not forwarded.
    [bool]$EmailAddressIsOK = $false
    $ForwardingAddress = ""
    Write-Host " "
    while (!$EmailAddressIsOK){
        Write-Host " "
        $ForwardingAddress = Read-Host "Enter email address to forward to"
        if ($ForwardingAddress -like "*@gables.com" -and (Get-Recipient -Identity $ForwardingAddress)){
            $EmailAddressIsOK = $true
        } else {Write-Host "The email address is not correct." -ForegroundColor Red}
    }
    Write-Host "Creating client forwarding rule..."
    try {New-InboxRule -Name ForwardAll -Mailbox $ADUser.mail -ForwardTo:$ForwardingAddress -Confirm:$false} catch {}
}

Start-Transcript -Path $LogPath -force
Connect-O365MFA
# Clear-Host

do {
    $ADUser = Get-User
    $WONumber = Read-Host "Enter Work Order number"
    if (!$ADUser) {Pause;exit}
    Write-Host
    Write-Host "Disabling account for" $ADUser.Name -ForegroundColor Yellow
    $confirmation = Read-Host "Are you Sure You Want To Proceed (Y/N)"
    if ($confirmation -eq 'y') {Disable-User $ADUser $WONumber}
    Write-Host
    Write-Host "Testing..."
    Check-UserIsDisabled $ADUser
    $again = Read-Host "Disable another user? (Y/N)"
} while ($again -eq 'y')

Write-Host "`nSynching..."
Start-ADSyncSyncCycle -PolicyType Delta -EA SilentlyContinue
Write-Host "`nFinished!"
Pause

Stop-Transcript
