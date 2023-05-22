# Cyber Mayhem

## TODOs

- Hardening de Tomcat.
- Buscar métodos de persistencia.
- Parchar LFI en PHP.

## Preparación

prep.sh
- Falta levantar el webserver.
```bash
#!/bin/bash
sshpass -p $2 ssh -o GlobalKnownHostsFile=/dev/null -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -t root@$1 "chmod -s /usr/bin/pkexec; cat /etc/sudoers; curl $3/sudoers.sh | bash; bash -l"
```

sudoers.sh
```bash
#!/bin/bash
grep -v -E "^root|Defaults|#|%|^s|^$" /etc/sudoers | while read -r entry; do user=$(echo $entry | awk '{print $1}'); substitution=$(echo $entry | sed "s/([^)]*)/($user)/g"); sed -i "s|$entry|$substitution|g" /etc/sudoers; done
```

## Blue Team

### Monitoreo

```bash
ps # Identificar sesión de ssh
ps -aux --forest # Ver procesos con sus hijos
w # Visualizar usuarios logueados
who # Visualizar usuarios logueados
```

### Apache

#### PHP.ini

Rutas:
- `/etc/php.ini`.
- `/etc/php/<version>/apache2/php.ini`.

```bash
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source

# Después de guardar cambios, reiniciar servicio
systemctl restart apache2
```

Probar si no afecta el healthcheck:

```bash
allow_url_fopen = Off
allow_url_include = Off
```

### Samba

Rutas:
- `/etc/samba/smb.conf`.

```bash
[global]
map to guest = never # Deshabilita sesión nula
usershare allow guests = no # Deshabilita sesión de guests
restrict anonymous = 2 # Probar con healthcheck

[myshare] # Probar con healthcheck
writeable = no
browseable = no
public = no
```

### FTP

*La configuración depende de que servicio de FTP se esté ejecutando.*

Rutas:
- `/etc/vsftpd.conf`

```bash
# /etc/vsftpd.conf
anonymous_enable=NO
write_enable=NO
anon_upload_enable=NO

# Ruta expuesta en FTP
chmod 755 /tmp/ftp # Probar healthcheck
```

## Red Team

### Persistencia

#### SSH

Local:

```bash
ssh-keygen -t rsa # Crear llave privada
cat id_rsa.pub | xclip -sel c
```

Intrusión:

```bash
echo '<pegar clipboard>' > <ruta de usuario>/.ssh/authorized_keys
```
