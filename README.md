# Offboard-Employee
Offboards a user in AD and O365 in a hybrid environment

# Description
- Disables a user in AD and O365 in a hybrid environment
- Disables AD account
- Move to 'Disabled Users' OU
- Change AD password
- Remove from groups
- Remove manager
- Disable OWA, ActiveSync
- Hide from address book
- Add comment to description
- Forward email
- Partial wipe mobile devices
- add user to litigation hold

# Requirements
- Powershell v4
- Powershell Active Directory Module
- Microsoft Online Services Sign-in Assistant / Windows Azure Active Directory Module
- Multi-Factor authentication for O365 module (Exchange Online Remote PowerShell Module) installed for the user running the script. 
- See: https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps
