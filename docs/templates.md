# Templates

## Box

### Distribución de archivos

```bash
Box
├── images
└── README.md
```

#### Contenido de `README.md`

````markdown
# <Box> <!-- omit from toc -->

*HackTheBox*
Write-up de la máquina <Box> de [HackTheBox](https://hackthebox.com).

*echoCTF*
Write-up de la máquina <box> de [echoCTF](https://echoCTF.red).

![Cover de <Box>](images/cover.png)

## Tabla de Contenido <!-- omit from toc -->

- [Introducción](#introducción)
  - [Técnicas vistas / Tags](#técnicas-vistas--tags)
  - [Estadísticas](#estadísticas)
- [Reconocimiento](#reconocimiento)
  - [Escaneo de host](#escaneo-de-host)
    - [Escaneo completo de puertos](#escaneo-completo-de-puertos)
    - [Escaneo específico](#escaneo-específico)
- [Enumeración](#enumeración)
  - [Servicios](#servicios)
    - [Nombre de servicio - Puerto](#nombre-de-servicio---puerto)
      - [Manual](#manual)
      - [Nombre de herramienta](#nombre-de-herramienta)
- [Explotación](#explotación)
  - [Tipo de explotación](#tipo-de-explotación)
    - [Pasos previos | Preparación](#pasos-previos--preparación)
    - [Ejecución](#ejecución)
- [Post Explotación](#post-explotación)
  - [Enumeración](#enumeración-1)
  - [Escalación de privilegios](#escalación-de-privilegios)
- [Conclusión](#conclusión)
- [Notas adicionales](#notas-adicionales)
- [Referencias](#referencias)


## Introducción

### Técnicas vistas / Tags

- Técnica 1
- Técnica 2
- Técnica 3

### Estadísticas

*HackTheBox*

| Característica | Descripción |
|---|---|
| Nombre | [<Box>](https://app.hackthebox.com/machines/<Box>) |
| OS | Windows / Linux |
| Dificultad oficial | Easy |
| Dificultad de comunidad | ![Dificultad](images/diff.png) |
| Puntos | 20 |
| Creadores | [Creator](https://app.hackthebox.com/users/Creator) |

*echoCTF*

| Característica | Descripción |
|---|---|
| Nombre | [nombre](https://echoctf.red/target/) |
| Dificultad | Expert |
| Banderas | 11 (7: other, 2: system, env, root) |
| Puntos | 6,600: (other: 1,600, system: 2,600, env: 900, root: 1,500) |
| Descripción/Pistas |  |

## Reconocimiento

### Escaneo de host

#### Escaneo completo de puertos

```bash
sudo nmap -T5 -open -vvv --min-rate=5000 -p- -n -Pn -oG nmap/all_ports $BOX_TARGET

```

#### Escaneo específico

```bash
nmap -sCV -p80,27017,37500 -oN nmap/targeted $BOX_TARGET

```

## Enumeración

### Servicios

#### Nombre de servicio - Puerto

##### Manual



##### Nombre de herramienta



## Explotación

### Tipo de explotación

#### Pasos previos | Preparación



#### Ejecución



## Post Explotación

### Enumeración



### Escalación de privilegios


## Conclusión


## Notas adicionales


## Referencias


````

## Compendio CTF / Writeup

```markdown
# Nombre CTF

## Tabla de Contenidos

## Resumen de Vulnerabilidades

## Web

### Web Reto 1

#### Info

| Atributo | Valor |
|---|---|
| Descripción | - |
| Archivos | - |

#### Solución

## Crypto

### Crypto Reto 1

#### Info

| Atributo | Valor |
|---|---|
| Descripción | - |
| Archivos | - |

#### Solución

## Reversing

### Reversing Reto 1

#### Info

| Atributo | Valor |
|---|---|
| Descripción | - |
| Archivos | - |

#### Solución

## Pwning

### Pwning Reto 1

#### Info

| Atributo | Valor |
|---|---|
| Descripción | - |
| Archivos | - |

#### Solución

## Forense

### Forense Reto 1

#### Info

| Atributo | Valor |
|---|---|
| Descripción | - |
| Archivos | - |

#### Solución

```
