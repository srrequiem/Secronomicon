# Kali-Environment

## Instalación utilerías

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y lsd bat
```

- [Oh my tmux](https://github.com/gpakosz/.tmux)
- [fzf](https://github.com/junegunn/fzf)

### .tmux.conf.local

```bash
tmux_conf_copy_to_os_clipboard=true
```

## .zshrc

```bash
[...]
# Comentar líneas siguientes
# some more ls aliases
#alias ll='ls -l'
#alias la='ls -A'
#alias l='ls -CF'
[...]

# Enable ~/.target file

export TARGET_FILE="$HOME/.target"

if ! [ -f "$TARGET_FILE" ]
then
    touch $TARGET_FILE
fi

export TARGET="$(cat $TARGET_FILE)"

# Custom aliases

alias ll='lsd -lh --group-dirs=first'
alias la='lsd -a --group-dirs=first'
alias l='lsd --group-dirs=first'
alias lla='lsd -lha --group-dirs=first'
alias ls='lsd --group-dirs=first'
alias cat='/bin/batcat'
alias catn='/bin/cat'
alias catnl='/bin/batcat --paging=never'

# Custom functions

function new_target(){
    # Usage: new_target <box name> <box IP>
    set_target $2
    mkdir -p $1/{nmap,content,exploits,scripts}
    cd $1
    tmux
}

function set_target(){
    # Usage: set_target <box IP>
    echo $1 > $TARGET_FILE
    export TARGET=$1
}

function clear_target(){
    echo '' > $TARGET_FILE
    unset TARGET
}

function extract_ports(){
    ports="$(cat $1 | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',')"
    ip_address="$(cat $1 | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort -u | head -n 1)"
    echo -e "\n[*] Extracting information...\n" > extractPorts.tmp
    echo -e "\t[*] IP Address: $ip_address"  >> extractPorts.tmp
    echo -e "\t[*] Open ports: $ports\n"  >> extractPorts.tmp
    echo $ports | tr -d '\n' | xclip -sel clip
    echo -e "[*] Ports copied to clipboard\n"  >> extractPorts.tmp
    cat extractPorts.tmp; rm extractPorts.tmp
}

function set_proxy() {
    # Usage: set_proxy <host> <port>
    export {http,https,ftp}_proxy="http://$1:$2"
}

function unset_proxy() {
    unset {http,https,ftp}_proxy
}

export PYENV_ROOT="$HOME/.pyenv"
command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"
```

## Scripts para xcfe4 (barra)

Click derecho a barra superior: `Panel/Add New Items...` &rarr; `Generic Monitor`

Ubicación: `/home/srrequiem/scripts`

### ethernet.sh

```bash
#!/bin/sh

echo "$(/usr/sbin/ifconfig eth0 | grep "inet " | awk '{print $2}')"
```

### vpn.sh

```bash
#!/bin/sh

IFACE=$(/usr/sbin/ifconfig | grep tun0 | awk '{print $1}' | tr -d ':')

if [ "$IFACE" = "tun0" ]
then
    echo "$(/usr/sbin/ifconfig tun0 | grep "inet " | awk '{print $2}')"
else
    echo "Disconnected"
fi
```

### target.sh

```bash
#!/bin/sh

TARGET=$(cat /home/srrequiem/.target)

if [ "$TARGET" = "" ]
then
    echo "None"
else
    cat /home/srrequiem/.target
fi
```
