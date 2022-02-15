You must download the .ps1, and the RuleProfiles directory and put them both in the same directory, like:

    .\Downloads\EEI_API_SetRules.ps1
    
    .\Downloads\RuleProfiles\...

Script usage: 

    powershell.exe -ExecutionPolicy bypass -F .\EEI_API_SetRules.ps1
    
    Follow the prompts to select a rule profile you want to use, and then provide Hostname and Credentials to allow sript to set the selecte d profile.
