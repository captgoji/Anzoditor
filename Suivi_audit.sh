#!/usr/bin/env bash
# Suivi d'un audit en cours : sur quel serveur, quel script, depuis combien de temps (lecture seule).
# Usage : ./suivi_audit.sh NomDuClient [--boucle [SECONDES]] [--lignes N] [--limit SRV1,SRV2]   (2e terminal)
#   --boucle 30 : rafraichit l'ecran toutes les 30 s (defaut) jusqu'a Ctrl+C, mots de passe demandes une seule fois
#   --lignes 5  : dernieres lignes du journal affichees pour chaque script en cours (defaut 3)
# Mots de passe : mdp= du .ini, sinon un par compte (comme lancer_audit.sh).

cd "$(dirname "$0")" || exit 1
export ANSIBLE_CONFIG="$(pwd)/ansible.cfg"
CLIENT="${1:-}"; FILE="clients/${CLIENT}.ini"
[ -n "$CLIENT" ] && [ -f "$FILE" ] || { echo "Usage : ./suivi_audit.sh NomDuClient"; exit 1; }
shift
BOUCLE=0; LIGNES=3; EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
    --boucle) BOUCLE=30; if [[ "${2:-}" =~ ^[0-9]+$ ]]; then BOUCLE=$2; shift; fi ;;
    --lignes) LIGNES="${2:-3}"; shift ;;
    --limit|-l) EXTRA+=("--limit" "${2:-all},localhost"); shift ;;   # localhost : tableau final
    *) EXTRA+=("$1") ;;
  esac
  shift
done

COMPTES=$(ansible-inventory -i "$FILE" --list 2>/dev/null | python3 -c '
import json, sys
inv = json.load(sys.stdin); hv = inv.get("_meta", {}).get("hostvars", {})
def hotes(g):
    d = inv.get(g, {}); r = list(d.get("hosts", []))
    for c in d.get("children", []): r += hotes(c)
    return r
vus = {}
for os_ in ("windows", "linux"):
    for h in hotes(os_):
        v = hv.get(h, {})
        if str(v.get("mdp") or ""):
            continue
        vus.setdefault((os_, str(v.get("compte") or v.get("ansible_user") or "defaut")), []).append(h)
for (os_, cle), hs in vus.items():
    print(os_ + "\t" + cle + "\t" + ", ".join(hs[:4]) + (" ..." if len(hs) > 4 else ""))
')
SECRETS=$(mktemp); chmod 600 "$SECRETS"; trap 'rm -f "$SECRETS"' EXIT
python3 - "$SECRETS" <<'PY' 3<<<"$COMPTES"
import getpass, json, os, sys
out = {"mdp_win": {}, "mdp_lin": {}}
for ligne in os.fdopen(3).read().splitlines():
    if ligne.strip():
        os_, cle, hotes = ligne.split("\t")
        k = "mdp_win" if os_ == "windows" else "mdp_lin"
        out[k][cle] = getpass.getpass(f"Mot de passe {'Windows' if os_ == 'windows' else 'SSH Linux'} de {cle}  ({hotes}) : ")
json.dump(out, open(sys.argv[1], "w"))
PY

SORTIE=$(mktemp); trap 'rm -f "$SECRETS" "$SORTIE"' EXIT
suivre() {
  : > "$SORTIE"
  ansible-playbook suivi.yml -i "$FILE" -e "@${SECRETS}" -e "suivi_fichier=${SORTIE}" -e "suivi_lignes=${LIGNES}" \
    "${EXTRA[@]}" > /dev/null 2>&1
  [ "$BOUCLE" -gt 0 ] && clear
  echo "=== Suivi de l'audit $CLIENT - $(date '+%H:%M:%S') ==="
  if [ -s "$SORTIE" ]; then cat "$SORTIE"; else echo "Echec du suivi : relancer avec   ansible-playbook suivi.yml -i $FILE   pour voir l'erreur"; fi
}
echo "Interrogation des serveurs..."
suivre
while [ "$BOUCLE" -gt 0 ]; do
  echo; echo "(rafraichissement toutes les ${BOUCLE} s - Ctrl+C pour quitter)"
  sleep "$BOUCLE"
  suivre
done