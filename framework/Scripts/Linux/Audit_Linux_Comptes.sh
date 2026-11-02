#!/usr/bin/env bash
# Audit_Linux_Comptes.sh
# Version      : 1.0
# Derniere modif : Creation - comptes locaux Linux au format de 11_Audit_comptes (Template_Audit_Comptes.xlsx)
# Role         : Liste les comptes locaux pouvant se connecter (UID 0, UID >= 1000, ou shell de connexion)
# Usage        : lance par ansible/audit.yml (module script, avec sudo si disponible), ou a la main :
#                sudo bash Audit_Linux_Comptes.sh
#                Sans root : pas de /etc/shadow (etat du mot de passe), crontabs, sudoers ni cles SSH des autres.
# Sortie       : CSV ";" sur stdout, colonnes de 11_Audit_comptes :
#                Ordinateur;Name;Type;DateCreation;Active;ReglageMdp;DateDesactivation;Description;
#                PasswordLastSet;DerniereConnexion;Groupes;Services;ScheduledTask
#                Type = "Compte local Linux (Tier 0)" pour root, UID 0, sudo/wheel/admin/docker/lxd/libvirt,
#                ou regle sudo -> ces lignes vont aussi dans <host>_Audit_comptes_T0.csv (tri fait par audit.yml)
# ============================================================

export LC_ALL=C
HOST="$(hostname 2>/dev/null)"
ROOT=0; [ "$(id -u)" -eq 0 ] && ROOT=1

csv() { local s="${1//\"/\"\"}"; printf '"%s"' "$s"; }
fmt_epoch() { [ -n "$1" ] && date -d "@$1" '+%d/%m/%Y %H:%M:%S' 2>/dev/null; }
fmt_jours() { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 > 0 )) && date -u -d "@$(( $1 * 86400 ))" '+%d/%m/%Y' 2>/dev/null; }
SHELLS_KO='nologin|false|sync|shutdown|halt'
GROUPES_ADMIN=' sudo wheel admin docker lxd libvirt '

# Derniere connexion : lastlog (ancien), lastlog2 (Debian 13+), sinon last (wtmp / wtmpdb)
derniere_connexion() {
    local u="$1" l d
    if command -v lastlog >/dev/null 2>&1; then
        l="$(timeout 10 lastlog -u "$u" 2>/dev/null | tail -n +2)"
        [[ "$l" == *"Never logged in"* || -z "$l" ]] || d="$(awk '{for(i=NF-5;i<=NF;i++) printf "%s ", $i}' <<<"$l")"
    fi
    if [ -z "$d" ] && command -v lastlog2 >/dev/null 2>&1; then
        l="$(timeout 10 lastlog2 -u "$u" 2>/dev/null | tail -n +2)"
        [[ "$l" == *"Never logged in"* || -z "$l" ]] || d="$(awk '{for(i=NF-5;i<=NF;i++) printf "%s ", $i}' <<<"$l")"
    fi
    if [ -z "$d" ] && command -v last >/dev/null 2>&1; then
        l="$(timeout 10 last -F -w -n 1 "$u" 2>/dev/null | head -1)"
        [[ "$l" == "$u "* ]] && d="$(awk '{print $4, $5, $6, $7, $8}' <<<"$l")"
    fi
    [ -n "$d" ] && date -d "$d" '+%d/%m/%Y %H:%M:%S' 2>/dev/null
}

# Services systemd en cours, par compte (User=)
declare -A SVC=()
while read -r id user; do
    [ -n "$user" ] && SVC["$user"]="${SVC[$user]:+${SVC[$user]} - }$id"
done < <(systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk '{print $1}' |
         xargs -r systemctl show -p Id -p User 2>/dev/null |
         awk -F= '/^Id=/{id=$2} /^User=/{print id, $2} /^$/{id=""}')

echo 'Ordinateur;Name;Type;DateCreation;Active;ReglageMdp;DateDesactivation;Description;PasswordLastSet;DerniereConnexion;Groupes;Services;ScheduledTask'

while IFS=: read -r u _ uid _ gecos home shell <&3; do
    shell_ok=1; [[ "$shell" =~ $SHELLS_KO || -z "$shell" ]] && shell_ok=0
    (( uid == 0 || (uid >= 1000 && uid != 65534) || shell_ok )) || continue

    groupes="$(id -nG "$u" 2>/dev/null)"
    t0=0; (( uid == 0 )) && t0=1
    for g in $groupes; do [[ "$GROUPES_ADMIN" == *" $g "* ]] && t0=1; done

    # Mot de passe (/etc/shadow : root uniquement)
    reglage=(); pls=""; desact=""; actif=Oui
    (( shell_ok )) || { actif=Non; reglage+=("Shell $shell"); }
    if (( ROOT )); then
        IFS=: read -r _ hash lastchg _ max _ _ expire _ < <(getent shadow "$u")
        case "$hash" in
            '')        reglage+=("SANS MOT DE PASSE") ;;
            '!'|'*'|'!*'|'!!') reglage+=("Pas de mot de passe (connexion par mot de passe impossible)") ;;
            '!'*)      reglage+=("Mot de passe verrouille") ;;
        esac
        [[ -z "$max" || "$max" == 99999 ]] && reglage+=("N'expire jamais") || reglage+=("Expire tous les $max jours")
        [[ "$lastchg" == 0 ]] && reglage+=("Changement force a la prochaine connexion")
        pls="$(fmt_jours "$lastchg")"
        if [[ "$expire" =~ ^[0-9]+$ ]]; then
            desact="$(fmt_jours "$expire")"
            (( expire * 86400 < $(date +%s) )) && { actif=Non; reglage+=("Compte expire"); }
        fi
        if sudo -n -l -U "$u" 2>/dev/null | grep -q 'may run'; then
            t0=1; reglage+=("Droits sudo")
        fi
    else
        reglage+=("Etat du mot de passe inconnu (audit sans sudo)")
    fi

    # Cles SSH autorisees
    ak="$home/.ssh/authorized_keys"
    if [ -r "$ak" ]; then
        nk=$(grep -cE '^[^#[:space:]]' "$ak" 2>/dev/null)
        (( nk > 0 )) && reglage+=("$nk cle(s) SSH")
    fi

    # Taches planifiees : crontab de l'utilisateur (root) + lignes de /etc/crontab et /etc/cron.d a son nom
    taches=""
    for f in /var/spool/cron/crontabs/"$u" /var/spool/cron/"$u"; do
        [ -r "$f" ] && taches="$(grep -vE '^\s*(#|$|[A-Z_]+=)' "$f" | awk '{$1=$2=$3=$4=$5=""; sub(/^ +/,""); print}' | head -5 | paste -sd'|' | sed 's/|/ - /g')"
    done
    sys="$(cat /etc/crontab /etc/cron.d/* 2>/dev/null | awk -v u="$u" '$0 !~ /^[[:space:]]*#/ && $6==u {print FILENAME}' | head -1)"
    [ -n "$sys" ] && taches="${taches:+$taches - }(cron systeme)"

    # Date de creation : pas d'equivalent sous Linux -> creation du repertoire personnel
    crea=""; [ -d "$home" ] && crea="$(fmt_epoch "$(stat -c %W "$home" 2>/dev/null | grep -v '^0$')")"

    type="Compte local Linux"; (( t0 )) && type="Compte local Linux (Tier 0)"
    desc="${gecos%%,*}"; [ -n "$desc" ] && desc="$desc ($home)" || desc="$home"

    printf '%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s\n' \
        "$(csv "$HOST")" "$(csv "$u")" "$(csv "$type")" "$(csv "$crea")" "$(csv "$actif")" \
        "$(csv "$(IFS='|'; echo "${reglage[*]}" | sed 's/|/ | /g')")" "$(csv "$desact")" "$(csv "$desc")" \
        "$(csv "$pls")" "$(csv "$(derniere_connexion "$u")")" "$(csv "${groupes// / - }")" \
        "$(csv "${SVC[$u]:-}")" "$(csv "$taches")"
done 3< <(getent passwd) </dev/null
exit 0
