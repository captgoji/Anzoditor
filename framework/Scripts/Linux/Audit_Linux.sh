#!/usr/bin/env bash
# Audit_Linux.sh
# Version      : 1.1
# Derniere modif : Ajout Virtualisation, Fabricant, Modèle, S/N (numero de serie : root requis -> lance avec sudo
#                  par audit.yml quand sudo fonctionne, sinon "(sudo requis)")
# Role         : Audit Linux : hostname, OS, materiel, interfaces, utilisateurs, services
# Usage        : lance par ansible/audit.yml (module script), ou a la main : sudo bash Audit_Linux.sh [IP]
#                Lecture seule.
# Sortie       : CSV ";" sur stdout (en-tete + 1 ligne), colonnes identiques a Template_Audit_Linux.xlsx :
#                Hostname;IP;OS;Virtualisation;Fabricant;Modèle;S/N;Interfaces;Utilisateurs;Services
# ============================================================

export LC_ALL=C
IP="${1:-}"
[ -z "$IP" ] && IP="$(hostname -I 2>/dev/null | awk '{print $1}')"

# Champ CSV entre guillemets (guillemets internes doubles)
csv() { local s="${1//\"/\"\"}"; printf '"%s"' "$s"; }
# Lignes non vides -> une seule chaine separee par " | "
joindre() { awk 'NF { gsub(/^[ \t]+|[ \t]+$/, ""); printf "%s%s", (n++ ? " | " : ""), $0 }'; }

HOST="$(hostname 2>/dev/null)"
OS="$( . /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-}" )"
[ -z "$OS" ] && OS="$(uname -sr)"

# Materiel (DMI) : fabricant / modele lisibles par tous, numero de serie reserve a root
dmi() { local v; v="$(cat "/sys/class/dmi/id/$1" 2>/dev/null)"; v="${v#"${v%%[![:space:]]*}"}"; echo "${v%"${v##*[![:space:]]}"}"; }
FABRICANT="$(dmi sys_vendor)"
MODELE="$(dmi product_name)"
SN="$(dmi product_serial)"
[ -z "$SN" ] && command -v dmidecode >/dev/null 2>&1 && SN="$(dmidecode -s system-serial-number 2>/dev/null | grep -v '^#' | head -1)"
if [ -z "$SN" ]; then
    if [ -e /sys/class/dmi/id/product_serial ] && [ "$(id -u)" -ne 0 ]; then SN="(sudo requis)"; else SN="(non disponible)"; fi
fi
VIRT="$(systemd-detect-virt 2>/dev/null)"
case "$VIRT" in
    none)  VIRT="Physique" ;;
    "")    VIRT="Inconnu" ;;
    lxc|lxc-libvirt|openvz|docker|podman|rkt|systemd-nspawn|wsl|proot|pouch)
           # conteneur : le DMI visible est celui de l'hote -> ne pas l'attribuer au conteneur
           VIRT="Conteneur ($VIRT)"; FABRICANT="-"; MODELE="-"; SN="(conteneur : voir l'hote)" ;;
    *)     VIRT="VM ($VIRT)" ;;
esac

if command -v ip >/dev/null 2>&1; then
    IFACES="$(ip addr show 2>/dev/null | grep -E 'inet |^[0-9]+:' | joindre)"
else
    IFACES="$(ifconfig 2>/dev/null | grep -E 'inet |^[a-z]' | joindre)"
fi

# UID >= 1000 avec un shell interactif : nom,UID,repertoire
USERS="$(getent passwd 2>/dev/null | awk -F: '$3>=1000 && $7!~/nologin|false|sync/ {print $1","$3","$6}' | joindre)"

# 30 premiers services systemd en cours d'execution
SERVICES="$(systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null \
            | awk '{ s = ($1 ~ /\.service$/) ? $1 : $2; print s }' | head -30 | joindre)"

echo 'Hostname;IP;OS;Virtualisation;Fabricant;Modèle;S/N;Interfaces;Utilisateurs;Services'
printf '%s;%s;%s;%s;%s;%s;%s;%s;%s;%s\n' "$(csv "$HOST")" "$(csv "$IP")" "$(csv "$OS")" \
       "$(csv "$VIRT")" "$(csv "$FABRICANT")" "$(csv "$MODELE")" "$(csv "$SN")" \
       "$(csv "$IFACES")" "$(csv "$USERS")" "$(csv "$SERVICES")"
exit 0
