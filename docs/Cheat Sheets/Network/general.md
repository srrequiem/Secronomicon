# Host discovery

## Ping Sweep

### Windows

#### Powershell

##### Opción 1

```powershell
# Ejecutar en límea de comandos o como script
1..255 | % {echo "172.16.2.$_"; ping -n 1 -w 100 172.16.2.$_} | Select-String ttl
```

##### Opción 2

```bash
# Pendiente sólo imprimir True
Import-Module Microsoft.PowerShell.Management

$ips = 1..255 | % { "192.168.1.$_" } 

$ips | ForEach-Object {
   
   $result = Test-Connection -Count 1 -ComputerName $_ -Quiet
   "$($_) $result"
}
```

#### MSDOS

```powershell
for /L %a in (1,1,254) do @start /b ping 192.168.0.%a -w 100 -n 2 >nul
arp -a
```

### Linux

#### Bash

##### Opción 1

```bash
fping -a -g X.X.X.0/24 2>/dev/null # Opción 1
```

##### Opción 2

```bash
#!/bin/bash
# host_discovery.sh
subnet="10.10.110."
for ip in {0..254}; do
  timeout 1 bash -c "ping -c 1 $subnet$ip" &> /dev/null && echo "[+] Host found $subnet$ip" &
done; wait
```

Ejecución:

```bash
bash host_discovery.sh
bash host_discovery.sh 2>/dev/null
```

##### Opción 3

```bash
subnet="10.10.110." && for ip in {0..254}; do ping -c 1 -t 1 $subnet$ip  > /dev/null && echo "[+] Host found $subnet$ip"; done
```


#### Nmap

```bash
nmap -sL 10.10.110.0/24 # List Scan
nmap -sP 10.10.110.0/24 # Ping Sweep
nmap -PS 10.10.110.0/24 # TCP SYN Ping
nmap -sA 10.10.110.0/24 # TCP ACK Ping
nmap -PE 10.10.110.0/24 # ICMP Echo Ping
```

# Port scanning

## TCP

### Netcat

```bash
netcat -v -z -n -w 1 <ip> 1-65535 > host.nc 2>&1
grep -v "refused" host.nc
```

### Bash

```bash
host=<ip>
for port in {1..65535}; do
  timeout 1 bash -c "echo >/dev/tcp/$host/$port" && echo "port $port is open" || echo "port $port is closed"
done
```

```bash
host=<ip>
for port in {1..65535}; do
  timeout 1 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null && echo "port $port is open"
done
```

### Nmap a través de pivote

```bash
seq 1 65535 | xargs -P 500 -I {} proxychains nmap -sT -Pn -p{} -open -T5 -v -n <ip> 2>&1 | grep "tcp open"
```

# MAC Address

## Cambio de MAC Address

1. Deshabilitar interfaz

```bash
ifconfig <interfaz de red> down
ifconfig wlan0 down
```

2. Cambiar valor asignado
   
```bash
ifconfig <interfaz de red> hw ether # Cambiar la dirección física (hardware address hw ether)
ifconfig wlan0 hw ether 00:11:22:33:44:55
```

3. Habilitar interfaz

```bash
ifconfig <interfaz de red> up
ifconfig wlan0 up
```

*Nota: Considerar que el cambio se realiza sólo en memoria, no físicamente por lo que regresará a su valor original una vez que se reinicie la máquina. En algunas ocasiones y dependiendo del chipset que se esté usando el valor regresará a su estado original **sin necesidad de reiniciar la máquina** si se experimenta dicha situación considerar buscar la solución en: https://www.youtube.com/watch?v=7AUGQNBCddo*