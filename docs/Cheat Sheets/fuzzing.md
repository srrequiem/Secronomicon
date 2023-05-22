# Fuzzing

Considerar diferencia de rutas respecto a archivos y directorios. No son lo mismo.
- /cgi-bin
- /cgi-bin/

Considerar códigos de estatus `500` como ruta existente aunque sea error de servidor.

Considerar sintaxis de `fuzzer` para búsqueda recursiva.
*TODO: Buscar sintaxis de ffuf y añadirlo a notas.*
Es decir: `http://sitio.com/FUZZ_padre/FUZZ_hijo`

Cuando se enumera un API tratar con el singular y el plural de la API considerando también los `ids` del endpoint. Por ejemplo:
- `http://10.10.10.10/FUZZ` revela `http://10.10.10.10/flows` y `flows` revela algunos ids.
- Considerar fuzzear `http://10.10.10.10/FUZZ/ID_encontrado`.
- Buscar el singular `http://10.10.10.10/flow/ID_encontrado`.

# ffuf

## Subdomain Discovery

`ffuf -c -w /path/to/vhost/wordlist -u https://target.com -H "Host: FUZZ.target.com" -ic`