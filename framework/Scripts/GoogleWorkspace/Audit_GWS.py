#!/usr/bin/env python3
# Audit_GWS.py
# Version      : 1.0
# Derniere modif : Creation - audit Google Workspace en LECTURE SEULE (Admin SDK Directory API)
# Role         : Comptes (2SV, derniere connexion, suspension, super admin), roles d'administration, groupes,
#                domaines et synthese securite du domaine Google Workspace d'un client.
# Connexion    : 2 modes (lecture seule dans les deux cas) :
#   1. Compte de service avec delegation au niveau du domaine (recommande, sans intervention) :
#        --cle cle_compte_service.json --admin admin@client.fr
#   2. Connexion dans le navigateur avec un compte super admin du client (comme M365) :
#        --client-oauth client_oauth.json [--admin admin@client.fr]
#      client_oauth.json = identifiant OAuth "Application de bureau" d'un projet Google Cloud de Netoptima.
# Usage        : lance par lancer_audit.sh si gws_domaine=... est renseigne dans [all:vars] du .ini, ou a la main :
#                python3 Audit_GWS.py --domaine client.fr --admin admin@client.fr --cle cle.json --sortie Temp_CSV/GWS
# Sorties      : <prefixe>_Audit_GWS_Comptes.csv, _Audit_GWS_Roles.csv, _Audit_GWS_Groupes.csv, _Audit_GWS_Securite.csv
# Dependances  : Python 3 standard ; mode compte de service : python3-cryptography (installe par defaut sur Ubuntu)
# ============================================================
import argparse
import base64
import csv
import hashlib
import http.server
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

SCOPES = ["https://www.googleapis.com/auth/admin.directory.user.readonly",
          "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
          "https://www.googleapis.com/auth/admin.directory.group.readonly",
          "https://www.googleapis.com/auth/admin.directory.domain.readonly",
          "https://www.googleapis.com/auth/admin.directory.customer.readonly"]
API = "https://admin.googleapis.com/admin/directory/v1"
TOKEN_URI = "https://oauth2.googleapis.com/token"
AUJ = datetime.now(timezone.utc)
INACTIF_J = 90
ROLES_SYSTEME = {"_SEED_ADMIN_ROLE": "Super administrateur", "_GROUPS_ADMIN_ROLE": "Administrateur des groupes",
                 "_GROUPS_EDITOR_ROLE": "Éditeur de groupes", "_GROUPS_READER_ROLE": "Lecteur de groupes",
                 "_USER_MANAGEMENT_ADMIN_ROLE": "Administrateur de la gestion des utilisateurs",
                 "_HELP_DESK_ADMIN_ROLE": "Administrateur de l'assistance", "_SERVICE_ADMIN_ROLE": "Administrateur des services",
                 "_MOBILE_ADMIN_ROLE": "Administrateur des appareils mobiles",
                 "_STORAGE_ADMIN_ROLE": "Administrateur de l'espace de stockage"}


class ErreurAPI(Exception):
    def __init__(self, code, msg):
        super().__init__(f"{code} {msg}")
        self.code = code


def post(url, data):
    req = urllib.request.Request(url, data=urllib.parse.urlencode(data).encode(), method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode())
        except Exception:
            return {"error": str(e)}
    except urllib.error.URLError as e:
        sys.exit(f"Google injoignable depuis cette machine ({e.reason}) : verifier l'acces Internet / proxy")


def b64(d):
    return base64.urlsafe_b64encode(d).rstrip(b"=").decode()


# ─── Connexion 1 : compte de service + delegation au niveau du domaine ───
def jeton_compte_service(cle, admin):
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError:
        sys.exit("python3-cryptography absent : sudo apt install python3-cryptography")
    k = json.load(open(cle, encoding="utf-8"))
    maint = int(time.time())
    entete = b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    corps = b64(json.dumps({"iss": k["client_email"], "sub": admin, "scope": " ".join(SCOPES),
                            "aud": k.get("token_uri", TOKEN_URI), "iat": maint, "exp": maint + 3600}).encode())
    cle_privee = serialization.load_pem_private_key(k["private_key"].encode(), password=None)
    signature = cle_privee.sign(f"{entete}.{corps}".encode(), padding.PKCS1v15(), hashes.SHA256())
    r = post(k.get("token_uri", TOKEN_URI), {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                             "assertion": f"{entete}.{corps}.{b64(signature)}"})
    if "access_token" not in r:
        sys.exit(f"Connexion Google refusee : {r.get('error_description') or r.get('error')} "
                 "(delegation au niveau du domaine et champs d'application autorises dans la console d'admin ?)")
    return r["access_token"]


# ─── Connexion 2 : navigateur (OAuth application de bureau, boucle locale) ───
def jeton_navigateur(fichier_client, admin):
    c = json.load(open(fichier_client, encoding="utf-8"))
    c = c.get("installed") or c.get("web") or c
    verif = secrets.token_urlsafe(64)
    defi = b64(hashlib.sha256(verif.encode()).digest())
    etat = secrets.token_urlsafe(16)
    recu = {}

    class Rappel(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            if q.get("state", [""])[0] == etat:
                recu.update({k: v[0] for k, v in q.items()})
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write("<h3>Connexion Google Workspace terminée, vous pouvez fermer cet onglet.</h3>".encode())

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Rappel)
    retour = f"http://127.0.0.1:{srv.server_port}/"
    url = c.get("auth_uri", "https://accounts.google.com/o/oauth2/auth") + "?" + urllib.parse.urlencode({
        "client_id": c["client_id"], "redirect_uri": retour, "response_type": "code", "scope": " ".join(SCOPES),
        "code_challenge": defi, "code_challenge_method": "S256", "state": etat, "access_type": "online",
        "prompt": "consent", **({"login_hint": admin} if admin else {})})
    print("\n" + "=" * 70)
    print(" GOOGLE WORKSPACE : connecte-toi avec un compte SUPER ADMIN du client")
    print(" Ouvrir ce lien dans le navigateur Windows (lecture seule) :\n")
    print(" " + url + "\n")
    print("=" * 70, flush=True)
    srv.timeout = 600
    fin = time.time() + 600
    while not recu and time.time() < fin:
        srv.handle_request()
    srv.server_close()
    if "code" not in recu:
        sys.exit(f"Connexion Google non terminee : {recu.get('error', 'delai depasse')}")
    r = post(c.get("token_uri", TOKEN_URI), {"grant_type": "authorization_code", "code": recu["code"],
                                             "client_id": c["client_id"], "client_secret": c.get("client_secret", ""),
                                             "redirect_uri": retour, "code_verifier": verif})
    if "access_token" not in r:
        sys.exit(f"Connexion Google refusee : {r.get('error_description') or r.get('error')}")
    print(" Connecte.\n", flush=True)
    return r["access_token"]


# ─── API ─────────────────────────────────────────────────────
class Google:
    def __init__(self, jeton):
        self.jeton = jeton

    def get(self, chemin, **params):
        url = f"{API}/{chemin}" + ("?" + urllib.parse.urlencode(params) if params else "")
        for essai in range(6):
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {self.jeton}"})
            try:
                with urllib.request.urlopen(req, timeout=120) as r:
                    return json.load(r)
            except urllib.error.HTTPError as e:
                if e.code in (429, 500, 503) and essai < 5:
                    time.sleep(5 * (essai + 1))
                    continue
                try:
                    msg = json.loads(e.read().decode()).get("error", {}).get("message", "")
                except Exception:
                    msg = ""
                raise ErreurAPI(e.code, msg)
            except urllib.error.URLError as e:
                if essai < 5:
                    time.sleep(5 * (essai + 1))
                    continue
                raise ErreurAPI(0, f"reseau : {e.reason}")

    def liste(self, chemin, cle, **params):
        res, jeton = [], None
        while True:
            p = dict(params, **({"pageToken": jeton} if jeton else {}))
            page = self.get(chemin, **p)
            res.extend(page.get(cle, []))
            jeton = page.get("nextPageToken")
            if not jeton:
                return res

    def essai(self, chemin, cle, **params):
        try:
            return self.liste(chemin, cle, **params), None
        except ErreurAPI as e:
            return None, f"Non disponible ({e})"


def dt(s):
    if not s:
        return None
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return None if d.year <= 1970 else d
    except ValueError:
        return None


def fr(d):
    return d.astimezone().strftime("%d/%m/%Y %H:%M:%S") if d else ""


def ecrire(chemin, colonnes, lignes):
    with open(chemin, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=colonnes, delimiter=";", quoting=csv.QUOTE_ALL, extrasaction="ignore")
        w.writeheader()
        w.writerows(lignes)


ON = lambda b: "Oui" if b else "Non"


def collecter(g, prefixe, sortie, domaine):
    users = g.liste("users", "users", customer="my_customer", maxResults=500, projection="basic",
                    fields="nextPageToken,users(id,primaryEmail,name/fullName,isAdmin,isDelegatedAdmin,suspended,"
                           "archived,creationTime,lastLoginTime,isEnrolledIn2Sv,isEnforcedIn2Sv,orgUnitPath,"
                           "changePasswordAtNextLogin)")
    par_id = {u["id"]: u for u in users}

    roles, e_roles = g.essai("customer/my_customer/roles", "items", maxResults=100)
    nom_role = {r["roleId"]: r.get("roleName", r["roleId"]) for r in roles or []}
    affect, e_aff = g.essai("customer/my_customer/roleassignments", "items", maxResults=200)
    roles_par_user, lignes_roles = {}, []
    for a in affect or []:
        role = nom_role.get(a.get("roleId"), a.get("roleId"))
        role = ROLES_SYSTEME.get(role, role)
        u = par_id.get(a.get("assignedTo"), {})
        if u:
            roles_par_user.setdefault(u["id"], set()).add(role)
        lignes_roles.append({"Role": role, "Membre": (u.get("name") or {}).get("fullName", "") or a.get("assignedTo"),
                             "Email": u.get("primaryEmail", ""),
                             "Type": "Utilisateur" if u else a.get("assigneeType", "Groupe / autre"),
                             "Actif": ON(not u.get("suspended")) if u else "",
                             "2SV": ON(u.get("isEnrolledIn2Sv")) if u else "",
                             "Derniere connexion": fr(dt(u.get("lastLoginTime"))) if u else "",
                             "Portee": a.get("scopeType", "")})
    # Super admins sans affectation listee (isAdmin)
    for u in users:
        if u.get("isAdmin") and "Super administrateur" not in roles_par_user.get(u["id"], set()):
            roles_par_user.setdefault(u["id"], set()).add("Super administrateur")
            lignes_roles.append({"Role": "Super administrateur", "Membre": (u.get("name") or {}).get("fullName", ""),
                                 "Email": u["primaryEmail"], "Type": "Utilisateur", "Actif": ON(not u.get("suspended")),
                                 "2SV": ON(u.get("isEnrolledIn2Sv")), "Derniere connexion": fr(dt(u.get("lastLoginTime"))),
                                 "Portee": "CUSTOMER"})
    lignes_roles.sort(key=lambda l: (l["Role"] != "Super administrateur", l["Role"], l["Email"]))

    comptes = []
    for u in users:
        dl = dt(u.get("lastLoginTime"))
        comptes.append({
            "Email": u["primaryEmail"], "Nom": (u.get("name") or {}).get("fullName", ""),
            "Unite organisationnelle": u.get("orgUnitPath", ""), "Actif": ON(not u.get("suspended")),
            "Archive": ON(u.get("archived")), "Super admin": ON(u.get("isAdmin")),
            "Admin delegue": ON(u.get("isDelegatedAdmin")),
            "Roles admin": ", ".join(sorted(roles_par_user.get(u["id"], []))),
            "Cree le": fr(dt(u.get("creationTime"))), "Derniere connexion": fr(dl), "Jamais connecte": ON(dl is None),
            "Inactif 90 j": ON(dl is None or dl < AUJ - timedelta(days=INACTIF_J)),
            "2SV active": ON(u.get("isEnrolledIn2Sv")), "2SV imposee": ON(u.get("isEnforcedIn2Sv")),
            "MDP a changer": ON(u.get("changePasswordAtNextLogin"))})

    groupes_l, e_grp = g.essai("groups", "groups", customer="my_customer", maxResults=200)
    groupes = [{"Email": x.get("email", ""), "Nom": x.get("name", ""),
                "Membres directs": x.get("directMembersCount", ""), "Description": x.get("description", "")}
               for x in groupes_l or []]
    doms, _ = g.essai("customer/my_customer/domains", "domains")

    # Synthese securite
    sec = []
    def ajout(p, val, st, com=""):
        sec.append({"Parametre": p, "Valeur": val, "Statut": st, "Commentaire": com})
    actifs = [c for c in comptes if c["Actif"] == "Oui" and c["Archive"] == "Non"]
    sa = [c for c in actifs if c["Super admin"] == "Oui"]
    ajout("Domaine", domaine, "Info", ", ".join(d.get("domainName", "") for d in doms or []))
    ajout("Comptes actifs / total", f"{len(actifs)} / {len(comptes)}", "Info",
          f"{sum(1 for c in comptes if c['Actif'] == 'Non')} suspendu(s) (licence éventuellement encore payée)")
    ajout("Super administrateurs", len(sa), "OK" if 2 <= len(sa) <= 4 else "Attention",
          "Recommandé : 2 à 4 ; " + ", ".join(c["Email"] for c in sa))
    sa_sans = [c["Email"] for c in sa if c["2SV active"] == "Non"]
    ajout("Super administrateurs sans validation en deux étapes", len(sa_sans), "OK" if not sa_sans else "Critique",
          ", ".join(sa_sans))
    sans = [c["Email"] for c in actifs if c["2SV active"] == "Non"]
    p = round(100 * len(sans) / len(actifs), 1) if actifs else 0
    ajout("Comptes actifs sans validation en deux étapes", f"{len(sans)} ({p} %)",
          "OK" if not sans else "Attention" if p <= 10 else "Critique", ", ".join(sans[:30]))
    non_imp = [c for c in actifs if c["2SV imposee"] == "Non"]
    ajout("Validation en deux étapes imposée", f"{len(actifs) - len(non_imp)} / {len(actifs)} comptes",
          "OK" if not non_imp else "Attention",
          "" if not non_imp else "Imposer la validation en deux étapes (Sécurité > Authentification) sur toutes les UO")
    inact = [c["Email"] for c in actifs if c["Inactif 90 j"] == "Oui"]
    ajout(f"Comptes actifs sans connexion depuis {INACTIF_J} jours", len(inact), "OK" if not inact else "Attention",
          ", ".join(inact[:30]))
    ajout("Rôles d'administration", len({l["Role"] for l in lignes_roles}), "Info", e_roles or e_aff or "")
    ajout("Groupes", len(groupes) if groupes_l is not None else e_grp, "Info")

    os.makedirs(sortie, exist_ok=True)
    b = os.path.join(sortie, prefixe)
    ecrire(f"{b}_Audit_GWS_Comptes.csv", list(comptes[0].keys()) if comptes else ["Email"], comptes)
    ecrire(f"{b}_Audit_GWS_Roles.csv", ["Role", "Membre", "Email", "Type", "Actif", "2SV", "Derniere connexion", "Portee"],
           lignes_roles)
    ecrire(f"{b}_Audit_GWS_Groupes.csv", ["Email", "Nom", "Membres directs", "Description"], groupes)
    ecrire(f"{b}_Audit_GWS_Securite.csv", ["Parametre", "Valeur", "Statut", "Commentaire"], sec)
    print(f"Google Workspace {domaine} : {len(comptes)} comptes ({len(actifs)} actifs), {len(sa)} super admin(s), "
          f"{len(sans)} compte(s) actif(s) sans 2SV, {len(groupes)} groupe(s)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--domaine", required=True)
    ap.add_argument("--admin", default="", help="super admin a utiliser (obligatoire avec --cle)")
    ap.add_argument("--cle", default="", help="cle JSON du compte de service (delegation au niveau du domaine)")
    ap.add_argument("--client-oauth", default="", help="client OAuth 'application de bureau' (connexion navigateur)")
    ap.add_argument("--sortie", required=True)
    ap.add_argument("--prefixe", default="")
    a = ap.parse_args()
    if a.cle:
        if not a.admin:
            sys.exit("--admin obligatoire avec un compte de service (gws_admin= dans le .ini)")
        jeton = jeton_compte_service(a.cle, a.admin)
    elif a.client_oauth and os.path.exists(a.client_oauth):
        jeton = jeton_navigateur(a.client_oauth, a.admin)
    else:
        sys.exit("Aucun moyen de connexion : gws_cle= (compte de service) dans le .ini, ou "
                 "framework/Scripts/GoogleWorkspace/client_oauth.json (connexion navigateur)")
    collecter(Google(jeton), a.prefixe or a.domaine.split(".")[0], a.sortie, a.domaine)


if __name__ == "__main__":
    main()
