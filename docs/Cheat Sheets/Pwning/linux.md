# Linux Pwning

## Validaciones iniciales

| Herramienta | Protección | Valor | Descripción |
|---|---|---|---|
| `file` | not stripped | NA | Indica que al hacer ingenieria inversa no se podrá ver el nombre de las funciones, etc. |
| `checksec` | PIE | PIE {enabled, disabled} | Cada vez que el programa se ejecute, contará con diferentes direcciones en memoria. |
| `checksec` | NX | NX {enabled, disabled} | Si esta deshabilitado indica que si se llegase a tener la capacidad de inyectar codigo en la pila se podrá ejecutar. |
| `checksec` | Stack CANARY | Canary found \| No canary found | Si se encuentra habilitado, las funciones cuentan con un valor aleatorio asignado si este valor se ve modificado el binario mostrará un mensaje de tipo `stack smashing detected`. |
| `checksec` | RELRO | {Full, PARTIAL} RELRO | Indica la capacidad que se tiene para la lectura y escritura. *TODO: Verificar mas adelante |

Usualmente el llamar directamente a la pila no retorna una shell, por lo que hay que buscar instrucciones de tipo `jmp` y `call`, pudiendo hacer un filtrado de estas instrucciones con `grep`. Ejemplo: `objdump -d [binario] | grep jmp`. Teniendo en cuenta que deberían apuntar a los ROP Gadgets ya sea de 32 o 64 bits respectivamente.

```bash
jmp: ff e0 (hexadecimal) *%rax
call: ff d0 (hexadecimal) *%rax
```

Para sacar offset en gdb:

- Setear breakpoint antes de que termine el programa
- Ejecutar:

```bash
info frame

x/24wx $rsp

p/d rip - rsp
```

## Debugging Local

### Consideraciones

Para debuggear localmente un binario tener en cuenta la protección `ASLR`.
- Para deshabilitar: `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`
- Para habilitar: `echo 2 | sudo tee /proc/sys/kernel/randomize_va_space`
- Para deshabilitar permanentemente, es necesario configurarlo en `sysctl`. Agregar el archivo `/etc/sysctl.d/01-disable-aslr.conf` con el contenido: `kernel.randomize_va_space = 0`

## GDB

set disassembly-flavor intel

## Script de exploit base

TODO

## Tips n' tricks

### getenvvar.c

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
   char *ptr;

   if(argc < 3) {
      printf("Usage: %s <environment var> <target program name>\n", argv[0]);
      exit(0);
   }
   ptr = getenv(argv[1]); /* Get env var location. */
   ptr += (strlen(argv[0]) - strlen(argv[2]))*2; /* Adjust for program name. */
   printf("%s will be at %p\n", argv[1], ptr);
}
```