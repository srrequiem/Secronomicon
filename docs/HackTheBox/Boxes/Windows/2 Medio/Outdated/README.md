# Introducción

## Técnicas vistas / Tags

- Técnica 1
- Técnica 2
- Técnica 3

## Estadísticas

| Característica | Descripción |
|---|---|
| Nombre | [Box]() |
| OS | Windows / Linux |
| Dificultad oficial | Easy |
| Dificultad de comunidad | ![Dificultad]() |
| Puntos | 20 |
| Creadores | [Creator]() |

# Reconocimiento

## Escaneo de host

### Escaneo completo de puertos

```bash
└─$ sudo nmap -sS --min-rate 5000 -open -vvv -p- -n -Pn -oG nmap/all_ports_ss $TARGET
[sudo] password for srrequiem:
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-11 19:12 EDT
Initiating SYN Stealth Scan at 19:12
Scanning 10.10.11.175 [65535 ports]
Discovered open port 139/tcp on 10.10.11.175
Discovered open port 25/tcp on 10.10.11.175
Discovered open port 445/tcp on 10.10.11.175
Discovered open port 53/tcp on 10.10.11.175
Discovered open port 135/tcp on 10.10.11.175
Discovered open port 593/tcp on 10.10.11.175
Discovered open port 49688/tcp on 10.10.11.175
Discovered open port 3269/tcp on 10.10.11.175
Discovered open port 49667/tcp on 10.10.11.175
Discovered open port 8530/tcp on 10.10.11.175
Discovered open port 3268/tcp on 10.10.11.175
Discovered open port 5985/tcp on 10.10.11.175
Discovered open port 9389/tcp on 10.10.11.175
Discovered open port 88/tcp on 10.10.11.175
Discovered open port 49687/tcp on 10.10.11.175
Discovered open port 58505/tcp on 10.10.11.175
Discovered open port 49929/tcp on 10.10.11.175
Discovered open port 49690/tcp on 10.10.11.175
Discovered open port 464/tcp on 10.10.11.175
Discovered open port 389/tcp on 10.10.11.175
Discovered open port 8531/tcp on 10.10.11.175
Discovered open port 636/tcp on 10.10.11.175
Completed SYN Stealth Scan at 19:12, 53.40s elapsed (65535 total ports)
Nmap scan report for 10.10.11.175
Host is up, received user-set (0.11s latency).
Scanned at 2022-10-11 19:12:00 EDT for 54s
Not shown: 65513 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
25/tcp    open  smtp             syn-ack ttl 127
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
8530/tcp  open  unknown          syn-ack ttl 127
8531/tcp  open  unknown          syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49687/tcp open  unknown          syn-ack ttl 127
49688/tcp open  unknown          syn-ack ttl 127
49690/tcp open  unknown          syn-ack ttl 127
49929/tcp open  unknown          syn-ack ttl 127
58505/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 53.49 seconds
           Raw packets sent: 262110 (11.533MB) | Rcvd: 48 (2.112KB)
```

### Escaneo específico

```bash
└─$ nmap -sCV -p 25,53,88,135,139,389,445,464,593,636,3268,3269,5985,8530,8531,9389,49667,49687,49688,49690,49929,58505 -n -Pn -oN nmap/targeted $TARGET
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-11 19:13 EDT
Nmap scan report for 10.10.11.175
Host is up (0.076s latency).

PORT      STATE SERVICE       VERSION
25/tcp    open  smtp          hMailServer smtpd
| smtp-commands: mail.outdated.htb, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-10-12 06:13:31Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2022-10-12T06:15:02+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC.outdated.htb, DNS:outdated.htb, DNS:OUTDATED
| Not valid before: 2022-06-18T05:50:24
|_Not valid after:  2024-06-18T06:00:24
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2022-10-12T06:15:02+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC.outdated.htb, DNS:outdated.htb, DNS:OUTDATED
| Not valid before: 2022-06-18T05:50:24
|_Not valid after:  2024-06-18T06:00:24
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC.outdated.htb, DNS:outdated.htb, DNS:OUTDATED
| Not valid before: 2022-06-18T05:50:24
|_Not valid after:  2024-06-18T06:00:24
|_ssl-date: 2022-10-12T06:15:02+00:00; +7h00m00s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC.outdated.htb, DNS:outdated.htb, DNS:OUTDATED
| Not valid before: 2022-06-18T05:50:24
|_Not valid after:  2024-06-18T06:00:24
|_ssl-date: 2022-10-12T06:15:02+00:00; +7h00m00s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8530/tcp  open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title.
8531/tcp  open  unknown
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49687/tcp open  msrpc         Microsoft Windows RPC
49688/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         Microsoft Windows RPC
49929/tcp open  msrpc         Microsoft Windows RPC
58505/tcp open  msrpc         Microsoft Windows RPC
Service Info: Hosts: mail.outdated.htb, DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h00m00s, deviation: 0s, median: 6h59m59s
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2022-10-12T06:14:24
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 98.51 seconds

```

# Enumeración

## Servicios

### Nombre de servicio - Puerto

#### Manual



#### Nombre de herramienta



# Explotación

## Tipo de explotación

### Pasos previos | Preparación



### Ejecución



# Post Explotación

## Enumeración



## Escalación de privilegios


# Conclusión


# Notas adicionales


# Referencias

