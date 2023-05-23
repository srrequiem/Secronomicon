# Pivoting & Port Forwarding

## Chisel

[Cheet Sheet completa por 0xdf](https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html)

### Servidor

```bash
chisel server -p 8000 --reverse
```

### Cliente

| Comando | Descripción |
|---|---|
| `chisel client 10.10.14.3:8000 R:80:127.0.0.1:80` | Escuchar en Kali 80, redireccionar a localhost puerto 80 en el cliente |
| `chisel client 10.10.14.3:8000 R:4444:10.10.10.240:80` | Escuchar en Kali 4444, redireccionar a 10.10.10.240 puerto 80 |
| `chisel client 10.10.14.3:8000 R:socks` | Crea un listener SOCKS5 en Kali (por default 1080), proxy a través de cliente |
| `chisel client 10.10.14.3:8000 R:1081:socks` | Crea un listener SOCKS5 en 1081 en Kali, proxy a través de cliente (configuración útil para múltiples clientes) |

### Proxychains

Configuración para múltiples clientes

```bash
# ...
dynamic_chain
#strict_chain
# ...
[ProxyList]
socks5	127.0.0.1 1081
socks5	127.0.0.1 1080
```

## SSH + Proxychains

### Redirección local de puertos

```bash
# Sintaxis
ssh -N -L bind_address:port:host:host_port [username@address]

# Setup
sudo ssh -N -L 0.0.0.0:445:192.168.1.110:445 student@10.11.0.128

# Uso
smbclient -L 127.0.0.1 -U Administrator
```

### Redirección remota de puertos

```bash
# Sintaxis
ssh -N -R bind_address:port:host:host_port [username@address]

# Setup
sudo ssh -N -R 10.11.0.4:2221:127.0.0.1:3306 kali@10.11.0.4

# Uso
TODO
```

### Redirección dinámica de puertos

```bash
# Sintaxis
ssh -N -D address_to_bind_to:port_to_bind_to [username@server_address]

# Setup
sudo ssh -N -D 127.0.0.1:8080 student@10.11.0.128
# Edición de Proxychains /etc/proxychains.conf
# [ProxyList]
#
#
# socks5  127.0.0.1 8080

## Uso
proxychains nmap --top-ports=20 -sT -Pn 192.168.1.110
```

### Parámetros SSH

- `-N` No levantará prompt de comandos.
- `-L` Indica redirección local.
- `-R` Indica redirección remota.
- `-D` Indica redirección dinámica.

## Socat

### Redirección local de puertos

```bash
# TCP
socat TCP-LISTEN:<puerto_local>,fork TCP:<ip>:<puerto>
```

## Windows - Redirección redirección de puertos

```powershell
# Requiere permisos de administrador
netsh interface portproxy add v4tov4 listenaddress=localaddress listenport=localport connectaddress=destaddress connectport=destport
```



