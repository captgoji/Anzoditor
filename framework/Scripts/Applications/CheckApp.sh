#!/usr/bin/env bash
# Liste les paquets installés (dpkg ou rpm) avec version, date d'installation
# et utilisateur ayant lancé l'installation.
# Sortie : CSV séparé par ";" sur stdout
#   hostname;name;version;install_date;source;publisher;installed_by;ports_ecoute;exposition;alerte
#
# À lancer en root (become) : les journaux apt / zypper ne sont pas lisibles sinon.
#
# Dates :
#  - Debian/Ubuntu : date du fichier /var/lib/dpkg/info/<pkg>.list
#  - RPM           : INSTALLTIME de la base rpm
#  -> dans les deux cas, date de la DERNIÈRE installation ou mise à jour.
#
# installed_by = utilisateur qui a INSTALLÉ le paquet (les mises à jour ultérieures,
# ex. unattended-upgrades ou dnf-automatic, ne l'écrasent pas) :
#  - Debian/Ubuntu : /var/log/apt/history.log* (champ Requested-By = vrai
#    utilisateur derrière sudo ; sinon "root" ou "unattended-upgrades")
#  - RHEL 8+/Fedora : historique dnf (user_id = utilisateur de connexion, même via sudo)
#  - RHEL/CentOS 7  : historique yum (loginuid)
#  - SUSE           : /var/log/zypp/history
#  Vide si l'info n'existe plus (paquets de l'installation initiale de l'OS,
#  journaux apt purgés par logrotate, installation via "dpkg -i" ou "rpm -i").
#
# ports_ecoute / exposition (via "ss -tulpn") :
#  - chaque port en écoute est rattaché au paquet qui fournit l'exécutable du processus
#    ex. "tcp:22 (sshd), tcp:127.0.0.1:25 (exim4)"
#    "tcp:22" = écoute sur toutes les interfaces ; sinon l'adresse est précisée
#  - exposition = RESEAU si au moins un port écoute ailleurs que sur 127.0.0.1/::1,
#    LOCAL si uniquement en local, vide si aucun port
#  - un processus en écoute qui ne vient d'aucun paquet (binaire dans /opt, script
#    maison, snap...) apparaît sur une ligne à part avec source = "processus"
#  NB : "en écoute sur le réseau" ne veut pas dire "joignable" : un pare-feu peut bloquer.
#
# Conteneurs (docker et podman) : une ligne par conteneur, démarré ou arrêté
#   name = nom du conteneur, version = tag de l'image (ou label de version),
#   install_date = date de création, source = docker:<état>, publisher = image
#   ports_ecoute = ports publiés sur l'hôte ("tcp:443->443"), ports en écoute si
#   le conteneur est en réseau "host", ou "interne:9200/tcp" pour un port
#   seulement accessible sur le réseau docker
#   exposition = RESEAU / LOCAL / INTERNE (joignable uniquement depuis les autres conteneurs)
#
# Option --detail-conteneurs : liste aussi les paquets (dpkg/rpm/apk) installés DANS
#   chaque conteneur démarré (source = dans:<conteneur>). Beaucoup plus de lignes.

#
# PHP et Node.js (colonne alerte) : chaque binaire php / php-fpm / node trouvé sur le
#   serveur (paquets, /opt, nvm, applis qui embarquent leur propre node comme
#   wazuh-dashboard...) et dans chaque conteneur démarré sort sur sa propre ligne :
#     source = php | nodejs | php:conteneur | nodejs:conteneur
#     alerte = OK / VULNERABLE (corrigé en x.y.z) / FIN DE VIE / A VERIFIER,
#              + "actif" si le binaire tourne (avec la commande lancée)
#   PHP     : PHP2Shell (CVE-2026-109618), corrigé en 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12
#   Node.js : CVE-2026-111497 (Brotli, RCE, publiée le 21/10/2026),
#             corrigé en 22.23.4 / 24.22.1 / 26.12.1 ; 20.x et avant = fin de vie
#   Les applis PHP connues (WordPress, GLPI, Dolibarr...) sortent avec source = appli-php.
#   NB : Debian/Ubuntu/RHEL corrigent souvent SANS changer le numéro de version
#   (backport) : un paquet de distribution marqué VULNERABLE est à vérifier dans son changelog.

PHP_FIXED="8.2.35 8.3.36 8.4.27 8.5.12"
NODE_FIXED="22.23.4 24.22.1 26.12.1"

DETAIL_CTR=0
[[ "${1:-}" == "--detail-conteneurs" ]] && DETAIL_CTR=1

set -u
export LC_ALL=C

HOST="$(hostname -f 2>/dev/null || hostname)"
# /etc/hosts mal renseigne (ex. "CT100.192.168.1.251") : nom court
case "$HOST" in *.*[!0-9.]*) ;; *) HOST="$(hostname 2>/dev/null)" ;; esac
fmt_epoch() { [[ -n "${1:-}" && "$1" =~ ^[0-9]+$ ]] && printf '%(%Y-%m-%d %H:%M:%S)T' "$1"; }

# Compare une version à la liste des versions corrigées (même branche majeure.mineure
# pour PHP, même majeure pour Node). $1 = php|node, $2 = version x.y.z
vuln_status() {
    local kind="$1" v="$2" f br fixed
    [[ "$v" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+) ]] || { echo "A VERIFIER (version illisible)"; return; }
    local M=${BASH_REMATCH[1]} m=${BASH_REMATCH[2]}
    if [[ "$kind" == php ]]; then
        if (( M < 8 || (M == 8 && m < 2) )); then echo "FIN DE VIE PHP $M.$m - plus de correctif"; return; fi
        br="$M.$m."; fixed="$PHP_FIXED"; cve="PHP2Shell CVE-2026-109618"
    else
        if (( M < 22 || M % 2 == 1 && M < 27 )); then echo "FIN DE VIE Node $M - plus de correctif"; return; fi
        br="$M."; fixed="$NODE_FIXED"; cve="CVE-2026-111497"
    fi
    for f in $fixed; do
        if [[ "$f" == "$br"* ]]; then
            if [[ "$(printf '%s\n%s\n' "$f" "$v" | sort -V | head -1)" == "$f" ]]; then echo "OK"
            else echo "VULNERABLE $cve (corrige en $f)"; fi
            return
        fi
    done
    echo "A VERIFIER (branche non listee)"
}

main() {
declare -A WHO=()

# --- Ports en écoute ---------------------------------------------------------
declare -A PORTS=() EXPO=() PNAME=() PEXE=() EXE2PKG=() PRINTED=() CTRNAME=() CTRIMG=() CTRSTATE=()

# chemin d'exécutable -> nom du paquet (résultat dans $PKG, avec cache)
find_pkg() {
    local exe="$1" c r=""
    if [[ -n "${EXE2PKG[$exe]+x}" ]]; then PKG="${EXE2PKG[$exe]}"; return; fi
    for c in "$exe" "$(readlink -f "$exe" 2>/dev/null)" "${exe#/usr}" "/usr$exe"; do
        [[ -z "$c" || ! "$c" == /* ]] && continue
        if command -v dpkg-query >/dev/null 2>&1; then
            r=$(dpkg-query -S "$c" 2>/dev/null | grep -v '^diversion' | head -1 | cut -d: -f1)
        elif command -v rpm >/dev/null 2>&1; then
            r=$(rpm -qf --qf '%{NAME}\n' "$c" 2>/dev/null | head -1) || r=""
        fi
        [[ -n "$r" ]] && break
    done
    EXE2PKG["$exe"]="$r"; PKG="$r"
}

add_port() {   # $1 = clé (paquet ou proc:...), $2 = entrée, $3 = LOCAL|RESEAU
    case ", ${PORTS[$1]:-}, " in *", $2, "*) ;; *) PORTS["$1"]="${PORTS[$1]:+${PORTS[$1]}, }$2" ;; esac
    local cur="${EXPO[$1]:-}"   # priorité : RESEAU > LOCAL > INTERNE
    if [[ -z "$cur" || "$3" == RESEAU || ( "$3" == LOCAL && "$cur" != RESEAU ) ]]; then EXPO["$1"]="$3"; fi
}

if command -v ss >/dev/null 2>&1; then
    while read -r proto _state _rq _sq local _peer rest; do
        [[ "$proto" == tcp || "$proto" == udp ]] || continue
        port="${local##*:}"; addr="${local%:*}"
        iface=""; [[ "$addr" == *%* ]] && { iface="${addr##*%}"; addr="${addr%%%*}"; }
        addr="${addr#[}"; addr="${addr%]}"
        case "$addr" in
            127.*|::1|::ffff:127.*) expo=LOCAL ;;
            *) expo=RESEAU ;;
        esac
        [[ "$iface" == lo ]] && expo=LOCAL
        case "$addr" in 0.0.0.0|'*'|::) where="" ;; *:*) where="[$addr]:" ;; *) where="$addr:" ;; esac

        pname="$(sed -n 's/.*users:(("\([^"]*\)".*/\1/p' <<<"$rest")"
        pid="$(grep -o 'pid=[0-9]*' <<<"$rest" | head -1 | cut -d= -f2)"
        exe=""
        if [[ -n "$pid" ]]; then
            exe="$(readlink "/proc/$pid/exe" 2>/dev/null)"; exe="${exe% (deleted)}"
        fi
        [[ -z "$pname" ]] && pname="inconnu"   # pas de processus visible (noyau, NFS, autre namespace)
        # Processus d'un conteneur (réseau "host") : identifiant du conteneur dans son cgroup
        ctr=""; [[ -n "$pid" ]] && ctr="$(grep -oE '[0-9a-f]{64}' "/proc/$pid/cgroup" 2>/dev/null | head -1)"
        if [[ -n "$ctr" ]]; then
            key="ctr:$ctr"
        else
            [[ -n "$exe" ]] && add_port "exe:$exe" "$proto:$where$port ($pname)" "$expo"
            PKG=""; [[ -n "$exe" ]] && find_pkg "$exe"
            if [[ -n "$PKG" ]]; then key="$PKG"; else key="proc:${exe:-$pname}"; PNAME["$key"]="$pname"; PEXE["$key"]="$exe"; fi
        fi
        add_port "$key" "$proto:$where$port ($pname)" "$expo"
    done < <(ss -tulpn 2>/dev/null | tail -n +2)
fi

out() {   # $1 = clé paquet ; ajoute les 2 colonnes ports/exposition
    PRINTED["$1"]=1
    printf ';%s;%s\n' "${PORTS[$1]:-}" "${EXPO[$1]:-}"
}

echo "hostname;name;version;install_date;source;publisher;installed_by;ports_ecoute;exposition;alerte"

# --- Debian / Ubuntu ---------------------------------------------------------
if command -v dpkg-query >/dev/null 2>&1 && [[ -d /var/lib/dpkg/info ]]; then
    declare -A MTIME=()
    while IFS='|' read -r f t; do
        n="${f##*/}"; n="${n%.list}"
        MTIME["$n"]="$t"
    done < <(find /var/lib/dpkg/info -maxdepth 1 -name '*.list' -printf '%p|%T@\n' 2>/dev/null)

    # Journaux apt, du plus ancien au plus récent (le dernier gagne)
    mapfile -t APTLOGS < <(ls -1 /var/log/apt/history.log* 2>/dev/null | sort -t. -k3,3nr)
    if (( ${#APTLOGS[@]} )); then
        while IFS=$'\t' read -r pkg who; do
            WHO["$pkg"]="$who"
        done < <(zcat -f "${APTLOGS[@]}" 2>/dev/null | awk '
            /^Start-Date:/   { user=""; cmd="" }
            /^Commandline:/  { cmd=$0 }
            /^Requested-By:/ { u=$0; sub(/^Requested-By: */,"",u); sub(/ *\(.*$/,"",u); user=u }
            /^Install:/ {
                who=user
                if (who=="") who=(cmd ~ /unattended-upgrade/ ? "unattended-upgrades" : "root")
                line=$0; sub(/^[A-Za-z]+: */,"",line)
                n=split(line, a, /\), /)
                for (i=1;i<=n;i++) { p=a[i]; sub(/ \(.*/,"",p); sub(/:.*/,"",p); gsub(/^ +/,"",p); if (p!="") print p "\t" who }
            }')
    fi

    while IFS=$'\t' read -r status pkg arch ver maint; do
        [[ "$status" == ii* ]] || continue
        t="${MTIME[$pkg]:-${MTIME[$pkg:$arch]:-}}"
        t="${t%%.*}"
        printf '%s;%s;%s;%s;dpkg;%s;%s' "$HOST" "$pkg" "$ver" "$(fmt_epoch "$t")" "${maint//;/,}" "${WHO[$pkg]:-}"
        out "$pkg"
    done < <(dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Architecture}\t${Version}\t${Maintainer}\n' 2>/dev/null)
fi

# --- RHEL / Fedora / SUSE ----------------------------------------------------
if command -v rpm >/dev/null 2>&1 && rpm -q rpm >/dev/null 2>&1; then

    # Historique dnf / yum (bases sqlite) via Python (présent sur toutes les RHEL)
    PY=""
    for c in python3 /usr/libexec/platform-python python2 python; do
        if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
    done
    if [[ -n "$PY" ]]; then
        while IFS=$'\t' read -r pkg who; do
            WHO["$pkg"]="$who"
        done < <("$PY" - 2>/dev/null <<'PYEOF'
import sqlite3, glob, os, pwd

def uname(uid):
    try:
        uid = int(uid)
    except (TypeError, ValueError):
        return ""
    if uid < 0 or uid == 4294967295:
        return "root"          # pas de session de connexion (cron, service...)
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return "uid:%d" % uid

res = {}

# dnf 4 (RHEL 8/9) et dnf 5 (Fedora 41+) - action 1 = Install
for db in ("/var/lib/dnf/history.sqlite",
           "/usr/lib/sysimage/libdnf5/transaction_history.sqlite"):
    if not os.path.exists(db):
        continue
    try:
        c = sqlite3.connect(db)
        q = ("SELECT r.name, t.user_id FROM trans_item ti "
             "JOIN trans t ON t.id = ti.trans_id "
             "JOIN rpm r ON r.item_id = ti.item_id "
             "WHERE ti.action = 1 ORDER BY t.id")
        for name, uid in c.execute(q):
            res[name] = uname(uid)
    except Exception:
        pass

# yum (RHEL/CentOS 7)
if not res:
    for db in sorted(glob.glob("/var/lib/yum/history/history-*.sqlite")):
        try:
            c = sqlite3.connect(db)
            q = ("SELECT p.name, b.loginuid FROM trans_data_pkgs d "
                 "JOIN trans_beg b ON b.tid = d.tid "
                 "JOIN pkgtups p ON p.pkgtupid = d.pkgtupid "
                 "WHERE d.state IN ('Install','True-Install','Dep-Install') "
                 "ORDER BY b.tid")
            for name, uid in c.execute(q):
                res[name] = uname(uid)
        except Exception:
            pass

for k, v in res.items():
    print("%s\t%s" % (k, v))
PYEOF
        )
    fi

    # SUSE : /var/log/zypp/history
    if [[ -r /var/log/zypp/history ]]; then
        while IFS=$'\t' read -r pkg who; do
            WHO["$pkg"]="$who"
        done < <(awk -F'|' '
            $2=="command" { u=$3; sub(/@.*/,"",u); cmduser=u }
            $2=="remove"  { delete seen[$3] }
            $2=="install" && !($3 in seen) { seen[$3]=1; u=$6; sub(/@.*/,"",u); if (u=="") u=cmduser; who[$3]=u }
            END { for (p in who) print p "\t" who[p] }
        ' /var/log/zypp/history)
    fi

    while IFS=$'\t' read -r name ver t vendor; do
        printf '%s;%s;%s;%s;rpm;%s;%s' "$HOST" "$name" "$ver" "$(fmt_epoch "$t")" "${vendor//;/,}" "${WHO[$name]:-}"
        out "$name"
    done < <(rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}.%{ARCH}\t%{INSTALLTIME}\t%{VENDOR}\n' 2>/dev/null | sort)
fi

# --- Flatpak -----------------------------------------------------------------
if command -v flatpak >/dev/null 2>&1; then
    while IFS=$'\t' read -r app ver; do
        [[ -n "$app" ]] && printf '%s;%s;%s;;flatpak;;;;\n' "$HOST" "$app" "$ver"
    done < <(flatpak list --app --columns=application,version 2>/dev/null)
fi

# --- Snap --------------------------------------------------------------------
if command -v snap >/dev/null 2>&1; then
    while read -r name ver _rest; do
        t="$(stat -c %Y "/snap/$name/current" 2>/dev/null || true)"
        printf '%s;%s;%s;%s;snap;;;;\n' "$HOST" "$name" "$ver" "$(fmt_epoch "$t")"
    done < <(snap list 2>/dev/null | tail -n +2)
fi

# --- Conteneurs (docker / podman) ---------------------------------------------
# docker exec peut rester bloque (runc init coince sur un hote sature) :
# delai court + SIGKILL, et on saute un conteneur qui ne repond pas a un "true".
CTR_TIMEOUT="${CTR_TIMEOUT:-45}"
declare -A CTRKO=()
cexec() {   # cexec RT CID script
    local rt="$1" cid="$2"; shift 2
    [[ -n "${CTRKO[$cid]:-}" ]] && return 1
    if ! timeout -k 3 10 "$rt" exec "$cid" true </dev/null >/dev/null 2>&1; then
        CTRKO["$cid"]=1
        echo "[CheckApp] conteneur ${CTRNAME[$cid]:-$cid} ne repond pas a '$rt exec', ignore" >&2
        return 1
    fi
    timeout -k 5 "$CTR_TIMEOUT" "$rt" exec "$cid" sh -c "$1" </dev/null 2>/dev/null
}
for RT in docker podman; do
    command -v "$RT" >/dev/null 2>&1 || continue
    mapfile -t CIDS < <("$RT" ps -aq --no-trunc 2>/dev/null)
    (( ${#CIDS[@]} )) || continue
    # --- tous les conteneurs en un seul appel
    US=$'\x1f'   # séparateur non blanc : préserve les champs vides
    while IFS="$US" read -r cid cname image state created netmode published exposed lver; do
        [[ -z "$cid" ]] && continue
        cname="${cname#/}"; key="ctr:$cid"
        # version : tag de l'image, sinon label org.opencontainers.image.version
        ref="${image%%@*}"; tag=""
        [[ "${ref##*/}" == *:* ]] && tag="${ref##*:}"
        [[ "$lver" == "<no value>" ]] && lver=""
        ver="$tag"; [[ -z "$ver" || "$ver" == latest ]] && ver="${lver:-${tag:-latest}}"
        [[ -n "$lver" && "$lver" != "$ver" ]] && ver="$ver ($lver)"
        # ports publiés : "IP|portHote|portCtr/proto "
        for b in $published; do
            IFS='|' read -r hip hport cport <<<"$b"
            proto="${cport#*/}"; cport="${cport%/*}"
            case "$hip" in 127.*|::1) e=LOCAL ;; *) e=RESEAU ;; esac
            case "$hip" in ''|0.0.0.0|::) w="" ;; *:*) w="[$hip]:" ;; *) w="$hip:" ;; esac
            add_port "$key" "$proto:$w$hport->$cport" "$e"
        done
        # ports exposés mais non publiés -> accessibles seulement sur le réseau docker
        if [[ "$netmode" != host && "$state" == running ]]; then
            for x in $exposed; do
                case " $published " in *"|$x "*) ;; *) add_port "$key" "interne:$x" INTERNE ;; esac
            done
        fi
        [[ "$netmode" == host ]] && image="$image (réseau host)"
        cdate="$(date -d "$created" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "${created:0:19}")"
        printf '%s;%s;%s;%s;%s:%s;%s;' "$HOST" "$cname" "${ver//;/,}" "$cdate" "$RT" "$state" "${image//;/,}"
        out "$key"
        CTRNAME["$cid"]="$cname"; CTRIMG["$cid"]="$image"; CTRSTATE["$cid"]="$state"
    done < <("$RT" inspect -f '{{.Id}}{{"\x1f"}}{{.Name}}{{"\x1f"}}{{.Config.Image}}{{"\x1f"}}{{.State.Status}}{{"\x1f"}}{{.Created}}{{"\x1f"}}{{.HostConfig.NetworkMode}}{{"\x1f"}}{{range $p,$b := .NetworkSettings.Ports}}{{range $b}}{{.HostIp}}|{{.HostPort}}|{{$p}} {{end}}{{end}}{{"\x1f"}}{{range $p,$v := .Config.ExposedPorts}}{{$p}} {{end}}{{"\x1f"}}{{index .Config.Labels "org.opencontainers.image.version"}}' "${CIDS[@]}" 2>/dev/null)

    # --- option : paquets installés dans chaque conteneur démarré
    if (( DETAIL_CTR )); then
        for cid in "${CIDS[@]}"; do
            [[ "${CTRSTATE[$cid]:-}" == running ]] || continue
            while IFS=$'\t' read -r pk pv; do
                [[ -n "$pk" ]] && printf '%s;%s;%s;;dans:%s;%s;;;\n' "$HOST" "$pk" "${pv//;/,}" "${CTRNAME[$cid]}" "${CTRIMG[$cid]//;/,}"
            done < <(cexec "$RT" "$cid" '
                if command -v dpkg-query >/dev/null 2>&1; then
                    dpkg-query -W -f="\${db:Status-Abbrev}\t\${Package}\t\${Version}\n" 2>/dev/null | awk -F"\t" "\$1 ~ /^ii/ {print \$2 \"\t\" \$3}"
                elif command -v rpm >/dev/null 2>&1; then
                    rpm -qa --qf "%{NAME}\t%{VERSION}-%{RELEASE}\n" 2>/dev/null
                elif command -v apk >/dev/null 2>&1; then
                    apk info -v 2>/dev/null | sed -E "s/-([0-9][^-]*-r[0-9]+)\$/\t\1/"
                fi' | sort)
        done
    fi

    # --- PHP / Node.js dans chaque conteneur démarré
    for cid in "${CIDS[@]}"; do
        [[ "${CTRSTATE[$cid]:-}" == running ]] || continue
        while IFS='|' read -r rpath rver; do
            [[ -z "$rpath" ]] && continue
            if [[ "$rver" =~ PHP\ ([0-9]+\.[0-9]+\.[0-9]+) ]]; then kind=php; label=PHP
            elif [[ "$rver" =~ ^v([0-9]+\.[0-9]+\.[0-9]+) ]]; then kind=node; label=Node.js
            else continue; fi
            v="${BASH_REMATCH[1]}"
            printf '%s;%s;%s;;%s:conteneur;%s:%s;;%s;%s;%s\n' "$HOST" "$label" "$v" "${kind/node/nodejs}" \
                "${CTRNAME[$cid]}" "$rpath" "${PORTS[ctr:$cid]:-}" "${EXPO[ctr:$cid]:-}" "$(vuln_status "$kind" "$v")"
        done < <(cexec "$RT" "$cid" '
            for p in $(command -v php node nodejs php-fpm 2>/dev/null; find /usr /opt /app /srv /home /var/www -maxdepth 6 -type f \( -name node -o -name nodejs -o -name php -o -name "php[0-9]*" -o -name "php-fpm*" \) 2>/dev/null); do
                [ -x "$p" ] || continue
                case "$p" in */node|*/nodejs) v=$("$p" --version 2>/dev/null) ;; *) v=$("$p" -v 2>/dev/null | head -1) ;; esac
                echo "$p|$v"
            done | sort -u')
    done
done

# --- PHP / Node.js sur l'hôte ----------------------------------------------------
declare -A EXECNT=() EXECMD=() SEEN=()
for d in /proc/[0-9]*; do       # processus en cours : exe -> nombre + 1re commande
    e="$(readlink "$d/exe" 2>/dev/null)"; e="${e% (deleted)}"
    [[ -z "$e" ]] && continue
    EXECNT["$e"]=$(( ${EXECNT[$e]:-0} + 1 ))
    if [[ -z "${EXECMD[$e]:-}" ]]; then
        c="$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null)"; c="${c//;/,}"; EXECMD["$e"]="${c:0:100}"
    fi
done
MODPHP=""
for a in apachectl apache2ctl httpd; do
    command -v "$a" >/dev/null 2>&1 && "$a" -M 2>/dev/null | grep -qi php && { MODPHP=" - mod_php charge dans apache"; break; }
done
{
    compgen -c | grep -E '^(php|php[0-9.]+|php-fpm[0-9.]*|php-cgi[0-9.]*|lsphp|frankenphp|node|nodejs)$' | while read -r b; do command -v "$b"; done
    find /usr/bin /usr/sbin /usr/local /opt /usr/share /usr/lib /srv /root /home -maxdepth 7 -type f \
        \( -name php -o -name 'php[0-9]*' -o -name 'php-fpm*' -o -name 'php-cgi*' -o -name 'lsphp*' -o -name frankenphp -o -name node -o -name nodejs \) \
        -not -path '*/node_modules/*' 2>/dev/null
    for e in "${!EXECNT[@]}"; do case "${e##*/}" in php*|node|nodejs|lsphp*|frankenphp) echo "$e" ;; esac; done
} | while read -r b; do readlink -f "$b" 2>/dev/null; done | sort -u | while read -r bin; do
    [[ -x "$bin" ]] || continue
    case "${bin##*/}" in
        node|nodejs) kind=node; label=Node.js; v="$(timeout 10 "$bin" --version </dev/null 2>/dev/null | grep -oE '^v[0-9]+\.[0-9]+\.[0-9]+' | tr -d v)" ;;
        *)           kind=php;  label=PHP;     v="$(timeout 10 "$bin" -v </dev/null 2>/dev/null | grep -oE 'PHP [0-9]+\.[0-9]+\.[0-9]+' | head -1 | cut -d' ' -f2)" ;;
    esac
    [[ -z "$v" ]] && continue
    st="$(vuln_status "$kind" "$v")"
    PKG=""; find_pkg "$bin"
    if [[ -n "$PKG" && "$st" != OK ]]; then
        # Backport distribution : le CVE est-il cité dans le changelog local du paquet ?
        [[ "$kind" == php ]] && cveid="CVE-2026-109618" || cveid="CVE-2026-111497"
        found=0
        for cl in /usr/share/doc/"$PKG"/changelog.Debian.gz /usr/share/doc/"$PKG"/changelog.gz; do
            [[ -r "$cl" ]] && zcat "$cl" 2>/dev/null | grep -q "$cveid" && found=1
        done
        if (( found )) || { command -v rpm >/dev/null 2>&1 && rpm -q --changelog "$PKG" 2>/dev/null | grep -q "$cveid"; }; then
            st="OK (backport distribution : $cveid corrige dans le paquet $PKG)"
        else
            st="$st - paquet $PKG : $cveid absent du changelog local, verifier"
        fi
    fi
    [[ "$kind" == php && -n "$MODPHP" ]] && st="$st$MODPHP"
    n="${EXECNT[$bin]:-0}"; (( n > 0 )) && st="$st - ACTIF ($n processus : ${EXECMD[$bin]})"
    pub="$bin"; [[ -n "$PKG" ]] && pub="$bin (paquet $PKG)"
    printf '%s;%s;%s;%s;%s;%s;;%s;%s;%s\n' "$HOST" "$label" "$v" "$(fmt_epoch "$(stat -c %Y "$bin" 2>/dev/null)")" \
        "${kind/node/nodejs}" "$pub" "${PORTS[exe:$bin]:-}" "${EXPO[exe:$bin]:-}" "$st"
done

# --- Applications PHP connues -------------------------------------------------
for root in /var/www /srv /usr/share/nginx /usr/share /home/*/public_html /home/*/www /opt; do
    [[ -d "$root" ]] || continue
    find "$root" -maxdepth 4 \( -name wp-config.php -o -path '*/inc/define.php' -o -name occ -o -path '*/app/etc/env.php' \
        -o -path '*/sites/default/settings.php' -o -name artisan -o -path '*/config/settings.inc.php' -o -name configuration.php \
        -o -path '*/htdocs/main.inc.php' -o -path '*/libraries/classes/Config.php' \) -type f 2>/dev/null
done | sort -u | while read -r f; do
    case "$f" in
        *wp-config.php) app="WordPress" ;; *inc/define.php) app="GLPI" ;; */occ) app="Nextcloud/ownCloud" ;;
        *app/etc/env.php) app="Magento" ;; *sites/default/settings.php) app="Drupal" ;; */artisan) app="Laravel" ;;
        *settings.inc.php) app="PrestaShop" ;; *configuration.php) app="Joomla ?" ;; *htdocs/main.inc.php) app="Dolibarr" ;;
        *Config.php) app="phpMyAdmin" ;; *) app="?" ;;
    esac
    printf '%s;%s;;;appli-php;%s;;;;\n' "$HOST" "$app" "$(dirname "$f")"
done

# --- Processus en écoute qui ne viennent d'aucun paquet -----------------------
for key in "${!PORTS[@]}"; do
    [[ -n "${PRINTED[$key]:-}" || "$key" == exe:* ]] && continue
    if [[ "$key" == ctr:* ]]; then   # conteneur non retrouvé par docker/podman
        printf '%s;conteneur %s;;;conteneur;;;%s;%s\n' "$HOST" "${key:4:12}" "${PORTS[$key]}" "${EXPO[$key]}"
    elif [[ "$key" == proc:* ]]; then
        printf '%s;%s;;;processus;%s;;%s;%s\n' "$HOST" "${PNAME[$key]}" "${PEXE[$key]:-}" "${PORTS[$key]}" "${EXPO[$key]}"
    else   # paquet trouvé mais pas listé plus haut (cas rare)
        printf '%s;%s;;;paquet;;;%s;%s\n' "$HOST" "$key" "${PORTS[$key]}" "${EXPO[$key]}"
    fi
done
}

# Toutes les lignes ont 10 colonnes : on ajoute une colonne "alerte" vide si besoin
main "$@" | awk -F';' '{ if (NF == 9) print $0 ";"; else print }'
exit 0