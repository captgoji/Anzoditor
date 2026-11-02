#!/usr/bin/env bash
# Lance audit.yml (framework NewAuditro) sur les serveurs d'un client.
# Usage : ./lancer_audit.sh NomDuClient [options ansible-playbook...]
#   ex. ./lancer_audit.sh FACO
#       ./lancer_audit.sh FACO --limit DC01,SRV-FIC01      (quelques serveurs seulement)
#       ./lancer_audit.sh FACO -e keep_remote=true          (garde C:\Windows\Temp\Audit_* pour diagnostiquer)
#       ./lancer_audit.sh FACO -e audit_apps=false          (sans inventaire des applications)
#       ./lancer_audit.sh FACO -e detail_conteneurs=true    (Linux : paquets dans les conteneurs)

cd "$(dirname "$0")" || exit 1
# Copie du rapport cote Windows (vide = pas de copie). Les fichiers ouverts depuis \\wsl.localhost
# s'ouvrent en mode protege dans Excel : les formules (synthese, plan d'action) n'y sont pas calculees.
COPIE_WINDOWS=""   # ex. /mnt/c/Users/aproteau/Documents/Audits
# Sous /mnt/c (dossier Windows), Ansible ignore un ansible.cfg du dossier courant (droits trop ouverts) :
# on le designe explicitement.
export ANSIBLE_CONFIG="$(pwd)/ansible.cfg"
CLIENT="${1:-}"
FILE="clients/${CLIENT}.ini"

if [ -z "$CLIENT" ]; then
  echo "Usage : ./lancer_audit.sh NomDuClient [options ansible-playbook]"
  echo "Clients disponibles :"
  ls clients/*.ini 2>/dev/null | xargs -n1 basename | sed 's/\.ini$//' | grep -v '^EXEMPLE$' | sed 's/^/  - /'
  exit 1
fi
shift
[ -f "$FILE" ] || { echo "Fichier introuvable : $FILE"; exit 1; }
for f in audit.yml profils.yml framework/Scripts/PowerShell framework/Scripts/Linux/Audit_Linux.sh framework/Process_excels.py; do
  [ -e "$f" ] || { echo "Manquant : $(pwd)/$f"; echo "Lien vers le framework : ln -s /mnt/c/chemin/NewAuditroV2 framework"; exit 1; }
done

DATE=$(date +%Y%m%d_%H%M)
NAME="${DATE}_${CLIENT}_audit"
OUT="rapports/${NAME}"
count() { ansible -i "$FILE" "$1" --list-hosts 2>/dev/null | grep -c '^    '; }
NB_LIN=$(count linux)
NB_WIN=$(count windows)
NB_RES=$(count reseau)
NB_ESX=$(count esxi)
NB_UNI=$(count unifi)
if [ "$NB_ESX" -gt 0 ] && ! python3 -c 'import pyVmomi' 2>/dev/null; then
  echo "ESXi / vCenter dans l'inventaire mais pyVmomi absent : sudo apt install python3-pyvmomi"; exit 1
fi
if [ "$NB_RES" -gt 0 ] && ! command -v snmpget >/dev/null; then
  echo "Equipements reseau dans l'inventaire mais outils SNMP absents : sudo apt install snmp"; exit 1
fi

echo "=== Client $CLIENT : $NB_WIN serveur(s) Windows, $NB_LIN serveur(s) Linux, $NB_RES equipement(s) reseau, $NB_ESX ESXi/vCenter, $NB_UNI controleur(s) UniFi ==="
echo "Pensez a connecter le VPN du client."
echo

# Mots de passe : mdp= (et mdp_sudo= pour Linux) dans le .ini -> aucune question pour ces serveurs.
# Sinon un mot de passe demande par compte : la cle est "compte=" si renseigne, sinon ansible_user
# (LAB\admin et PROD\admin = deux questions ; meme compte local sur des VM differentes -> compte=vm1, compte=vm2).
# Les mots de passe vont dans un fichier temporaire (droits 600) supprime a la fin, jamais sur la ligne de commande.
COMPTES=$(ansible-inventory -i "$FILE" --list 2>/dev/null | python3 -c '
import json, sys
inv = json.load(sys.stdin); hv = inv.get("_meta", {}).get("hostvars", {})
def hotes(g):
    d = inv.get(g, {}); r = list(d.get("hosts", []))
    for c in d.get("children", []): r += hotes(c)
    return r
vus = []
for os_ in ("windows", "linux", "esxi", "unifi"):
    for h in hotes(os_):
        v = hv.get(h, {}); cle = str(v.get("compte") or v.get("ansible_user") or "defaut")
        if str(v.get("mdp") or ""):
            continue   # mot de passe dans le .ini
        if (os_, cle) not in [(a, b) for a, b, _ in vus]:
            vus.append((os_, cle, [h]))
        else:
            next(x for x in vus if x[0] == os_ and x[1] == cle)[2].append(h)
for os_, cle, hs in vus:
    print(os_ + "\t" + cle + "\t" + ", ".join(hs[:4]) + (" ..." if len(hs) > 4 else ""))
')
SECRETS=$(mktemp); chmod 600 "$SECRETS"; trap 'rm -f "$SECRETS"' EXIT
python3 - "$SECRETS" <<'PY' 3<<<"$COMPTES"
import getpass, json, os, sys
out = {"mdp_win": {}, "mdp_lin": {}, "mdp_sudo_lin": {}, "mdp_esxi": {}, "mdp_unifi": {}}
for ligne in os.fdopen(3).read().splitlines():
    if not ligne.strip():
        continue
    os_, cle, hotes = ligne.split("\t")
    if os_ == "windows":
        out["mdp_win"][cle] = getpass.getpass(f"Mot de passe Windows de {cle}  ({hotes}) : ")
    elif os_ == "esxi":
        out["mdp_esxi"][cle] = getpass.getpass(f"Mot de passe vSphere de {cle}  ({hotes}) : ")
    elif os_ == "unifi":
        out["mdp_unifi"][cle] = getpass.getpass(f"Mot de passe du controleur UniFi pour {cle}  ({hotes}) : ")
    else:
        out["mdp_lin"][cle] = getpass.getpass(f"Mot de passe SSH Linux de {cle}  ({hotes}) (Entree si cle SSH) : ")
        out["mdp_sudo_lin"][cle] = getpass.getpass("   mot de passe sudo (Entree si identique) : ") or out["mdp_lin"][cle]
json.dump(out, open(sys.argv[1], "w"))
PY
echo

# Microsoft 365 : m365_tenant=client.onmicrosoft.com dans [all:vars] du .ini -> connexion par code avec un compte
# admin du client, collecte Graph (lecture seule) dans le rapport, avant l'audit des serveurs.
# Pour l'ignorer sur un lancement : SANS_M365=1 ./lancer_audit.sh CLIENT
M365_TENANT=$(grep -E '^[[:space:]]*m365_tenant[[:space:]]*=' "$FILE" | tail -1 | cut -d= -f2- | tr -d "'\" \r")
if [ -n "$M365_TENANT" ] && [ -z "${SANS_M365:-}" ]; then
  mkdir -p "$OUT/Temp_CSV/M365" "$OUT/logs/M365"
  python3 -u framework/Scripts/M365/Audit_M365.py --tenant "$M365_TENANT" --sortie "$OUT/Temp_CSV/M365" \
    --prefixe "$CLIENT" 2>&1 | tee "$OUT/logs/M365/Audit_M365.log"
  [ "${PIPESTATUS[0]}" -eq 0 ] || echo "ATTENTION : audit M365 en erreur (voir $OUT/logs/M365/Audit_M365.log), suite de l'audit"
  echo
fi

# Google Workspace : gws_domaine=client.fr dans [all:vars] (+ gws_admin=superadmin@client.fr)
#   - avec gws_cle='/chemin/cle.json' : compte de service avec delegation au niveau du domaine (sans intervention)
#   - sinon : lien de connexion a ouvrir dans le navigateur avec un super admin du client
#             (necessite framework/Scripts/GoogleWorkspace/client_oauth.json)
# Pour l'ignorer sur un lancement : SANS_GWS=1 ./lancer_audit.sh CLIENT
valeur_ini() { grep -E "^[[:space:]]*$1[[:space:]]*=" "$FILE" | tail -1 | cut -d= -f2- | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e "s/^['\"]//" -e "s/['\"]$//" | tr -d '\r'; }
GWS_DOMAINE=$(valeur_ini gws_domaine)
if [ -n "$GWS_DOMAINE" ] && [ -z "${SANS_GWS:-}" ]; then
  mkdir -p "$OUT/Temp_CSV/GWS" "$OUT/logs/GWS"
  GWS_CLE=$(valeur_ini gws_cle); GWS_CLE="${GWS_CLE/#\~/$HOME}"
  python3 -u framework/Scripts/GoogleWorkspace/Audit_GWS.py --domaine "$GWS_DOMAINE" --admin "$(valeur_ini gws_admin)" \
    ${GWS_CLE:+--cle "$GWS_CLE"} --client-oauth framework/Scripts/GoogleWorkspace/client_oauth.json \
    --sortie "$OUT/Temp_CSV/GWS" --prefixe "$CLIENT" 2>&1 | tee "$OUT/logs/GWS/Audit_GWS.log"
  [ "${PIPESTATUS[0]}" -eq 0 ] || echo "ATTENTION : audit Google Workspace en erreur (voir $OUT/logs/GWS/Audit_GWS.log), suite de l'audit"
  echo
fi

ansible-playbook audit.yml -i "$FILE" -e "report_name=${NAME}" -e "@${SECRETS}" \
  -e win_password=- -e linux_password=- -e linux_become_password=- "$@"

echo
echo "=================================================================="
echo " Statut   : $OUT/statut.csv"
echo " CSV      : $OUT/Temp_CSV/"
echo " Excel    : $OUT/Excel/"
echo " Logs     : $OUT/logs/<serveur>/"
if [ -f "$OUT/statut.csv" ]; then
  NB_KO=$(tail -n +2 "$OUT/statut.csv" | grep -vc ';OK$')
  [ "$NB_KO" -gt 0 ] && echo " ATTENTION : $NB_KO serveur(s) pas entierement OK, voir le statut"
fi
if [ -n "$COPIE_WINDOWS" ] && [ -d "$OUT" ]; then
  mkdir -p "$COPIE_WINDOWS" && cp -r "$OUT" "$COPIE_WINDOWS/" && OUT="$COPIE_WINDOWS/$NAME"
fi
command -v wslpath >/dev/null && echo " Depuis Windows : $(wslpath -w "$OUT")"
echo "=================================================================="
