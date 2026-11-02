#!/usr/bin/env python3
# Audit_M365.py
# Version      : 1.1
# Derniere modif : Analyse du contenu des protections Entra ID / Intune (Audit_M365_Securite.py) : acces conditionnel,
#                  methodes d'authentification, strategies Intune (BitLocker, LAPS, Defender, ASR, pare-feu, Autorun,
#                  Windows Update...), appareils geres, cles BitLocker ; nouvelles autorisations Intune en lecture
# v1.0         : Creation - remplace 12_Audit_Comptes_365.ps1 pour l'audit via Ansible (machine WSL) :
#                  comptes + licences + connexions (meme CSV que 12_), MFA, roles d'administration, invites,
#                  parametres de securite du tenant, appareils Entra ID et LAPS
# Role         : Interroge Microsoft Graph en LECTURE SEULE avec le compte admin du client (connexion par code :
#                le script affiche un code a saisir sur https://microsoft.com/devicelogin, MFA comprise).
#                Application utilisee : "Microsoft Graph Command Line Tools" (celle de Connect-MgGraph) ;
#                a la premiere connexion sur un tenant, un administrateur global doit accepter les autorisations.
# Usage        : lance par lancer_audit.sh si m365_tenant=... est renseigne dans [all:vars] du .ini, ou a la main :
#                python3 Audit_M365.py --tenant client.onmicrosoft.com --sortie Temp_CSV/M365 [--prefixe CLIENT]
# Sorties      : <prefixe>_Audit_Comptes_365.csv   (colonnes de 12_ + Actif, Type, MFA, Roles admin, Synchronise AD)
#                <prefixe>_Audit_M365_Roles.csv     membres des roles d'administration
#                <prefixe>_Audit_M365_Invites.csv   comptes invites
#                <prefixe>_Audit_M365_Securite.csv  parametres du tenant (securite par defaut, acces conditionnel...)
#                <prefixe>_Audit_M365_Appareils.csv appareils Entra ID + sauvegarde LAPS
# Licences     : derniere connexion, MFA par utilisateur et acces conditionnel demandent Entra ID P1 ;
#                sans P1 les colonnes concernees valent "Non disponible (licence Entra ID P1 requise)".
# Dependances  : Python 3 standard uniquement (urllib) ; aucun mot de passe ni jeton n'est ecrit sur disque.
# ============================================================
import argparse
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"   # Microsoft Graph Command Line Tools (Connect-MgGraph)
SCOPES = ["User.Read.All", "Directory.Read.All", "AuditLog.Read.All", "UserAuthenticationMethod.Read.All",
          "RoleManagement.Read.Directory", "Policy.Read.All", "Device.Read.All",
          "DeviceLocalCredential.ReadBasic.All", "Organization.Read.All",
          "DeviceManagementConfiguration.Read.All", "DeviceManagementManagedDevices.Read.All",
          "BitlockerKey.ReadBasic.All"]
GRAPH = "https://graph.microsoft.com"
NON_P1 = "Non disponible (licence Entra ID P1 requise)"
AUJ = datetime.now(timezone.utc)
SEUIL_6M = AUJ - timedelta(days=182)


class ErreurGraph(Exception):
    def __init__(self, code, msg):
        super().__init__(f"{code} {msg}")
        self.code = code


# ─── CONNEXION (code a l'ecran) ─────────────────────────────
def post(url, data):
    req = urllib.request.Request(url, data=urllib.parse.urlencode(data).encode(), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode() or "{}")
    except urllib.error.URLError as e:
        sys.exit(f"Microsoft 365 injoignable depuis cette machine ({e.reason}) : verifier l'acces Internet / proxy")


def connexion(tenant):
    base = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0"
    scope = " ".join(f"{GRAPH}/{s}" for s in SCOPES) + " offline_access"
    dc = post(f"{base}/devicecode", {"client_id": CLIENT_ID, "scope": scope})
    if "device_code" not in dc:
        sys.exit(f"Connexion M365 impossible : {dc.get('error_description') or dc}")
    print("\n" + "=" * 70)
    print(" MICROSOFT 365 : connecte-toi avec un compte ADMIN du client")
    print(f"   1. ouvrir   {dc.get('verification_uri', 'https://microsoft.com/devicelogin')}")
    print(f"   2. saisir   {dc['user_code']}")
    print("   (lecture seule ; 1re fois sur ce tenant : cocher le consentement pour l'organisation)")
    print("=" * 70, flush=True)
    fin = time.time() + int(dc.get("expires_in", 900))
    pause = int(dc.get("interval", 5))
    while time.time() < fin:
        time.sleep(pause)
        t = post(f"{base}/token", {"grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                                   "client_id": CLIENT_ID, "device_code": dc["device_code"]})
        if "access_token" in t:
            print(" Connecte.\n", flush=True)
            return t["access_token"]
        err = t.get("error")
        if err == "slow_down":
            pause += 5
        elif err != "authorization_pending":
            sys.exit(f"Connexion M365 refusee : {t.get('error_description', err)}")
    sys.exit("Connexion M365 : delai depasse (code non saisi)")


# ─── GRAPH ──────────────────────────────────────────────────
class Graph:
    def __init__(self, jeton):
        self.jeton = jeton

    def get(self, chemin, version="v1.0", entetes=None):
        url = chemin if chemin.startswith("http") else f"{GRAPH}/{version}/{chemin.lstrip('/')}"
        for essai in range(6):
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {self.jeton}",
                                                       "ConsistencyLevel": "eventual", **(entetes or {})})
            try:
                with urllib.request.urlopen(req, timeout=120) as r:
                    return json.load(r)
            except urllib.error.HTTPError as e:
                if e.code in (429, 503, 504) and essai < 5:
                    time.sleep(int(e.headers.get("Retry-After", 5 * (essai + 1))))
                    continue
                try:
                    msg = json.loads(e.read().decode()).get("error", {}).get("message", "")
                except Exception:
                    msg = ""
                raise ErreurGraph(e.code, msg)
            except urllib.error.URLError as e:
                if essai < 5:
                    time.sleep(5 * (essai + 1))
                    continue
                raise ErreurGraph(0, f"reseau : {e.reason}")
        raise ErreurGraph(429, "trop de requetes")

    def liste(self, chemin, version="v1.0"):
        res, page = [], self.get(chemin, version)
        while True:
            res.extend(page.get("value", []))
            suivant = page.get("@odata.nextLink")
            if not suivant:
                return res
            page = self.get(suivant)

    def essai(self, chemin, version="v1.0", liste=True):
        """(donnees, None) ou (None, raison) - 403 sans P1 / sans droit, 400 non pris en charge."""
        try:
            return (self.liste(chemin, version) if liste else self.get(chemin, version)), None
        except ErreurGraph as e:
            if e.code in (401, 403):
                return None, NON_P1 if "premium" in str(e).lower() or "license" in str(e).lower() \
                    else f"Accès refusé ({e})"
            return None, f"Non disponible ({e})"


# ─── OUTILS ─────────────────────────────────────────────────
def dt(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def fr(d):
    return d.astimezone().strftime("%d/%m/%Y %H:%M:%S") if d else ""


def ecrire(chemin, colonnes, lignes):
    with open(chemin, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=colonnes, delimiter=";", quoting=csv.QUOTE_ALL, extrasaction="ignore")
        w.writeheader()
        for l in lignes:
            w.writerow(l)


METHODES = {"microsoftAuthenticatorPush": "Authenticator", "microsoftAuthenticatorPasswordless": "Authenticator sans MDP",
            "softwareOneTimePasscode": "Code TOTP", "hardwareOneTimePasscode": "Jeton matériel",
            "mobilePhone": "SMS / appel", "alternateMobilePhone": "Tel. secondaire", "officePhone": "Tel. bureau",
            "email": "E-mail (SSPR)", "fido2": "Clé FIDO2", "windowsHelloForBusiness": "Windows Hello",
            "passKeyDeviceBound": "Passkey", "passKeyDeviceBoundAuthenticator": "Passkey Authenticator",
            "temporaryAccessPass": "TAP", "securityQuestion": "Questions"}
TYPES_METHODE = {"#microsoft.graph.microsoftAuthenticatorAuthenticationMethod": "Authenticator",
                 "#microsoft.graph.phoneAuthenticationMethod": "SMS / appel",
                 "#microsoft.graph.softwareOathAuthenticationMethod": "Code TOTP",
                 "#microsoft.graph.fido2AuthenticationMethod": "Clé FIDO2",
                 "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod": "Windows Hello",
                 "#microsoft.graph.temporaryAccessPassAuthenticationMethod": "TAP",
                 "#microsoft.graph.emailAuthenticationMethod": "E-mail (SSPR)"}
FORTES = {"Authenticator", "Authenticator sans MDP", "Code TOTP", "Jeton matériel", "SMS / appel", "Tel. secondaire",
          "Tel. bureau", "Clé FIDO2", "Windows Hello", "Passkey", "Passkey Authenticator"}


# ─── COLLECTE ───────────────────────────────────────────────
def collecter(g, prefixe, sortie):
    org, _ = g.essai("organization", liste=True)
    nom_tenant = (org or [{}])[0].get("displayName", "")

    # Licences
    skus, _ = g.essai("subscribedSkus")
    sku_nom, plan_nom = {}, {}
    for s in skus or []:
        sku_nom[s["skuId"]] = s.get("skuPartNumber", s["skuId"])
        for p in s.get("servicePlans", []):
            plan_nom[p["servicePlanId"]] = f"{p.get('servicePlanName')} [{s.get('skuPartNumber')}]"
    p1 = any(p.get("servicePlanName", "").startswith(("AAD_PREMIUM", "AAD_PREMIUM_P2"))
             for s in skus or [] for p in s.get("servicePlans", []))

    # Utilisateurs (signInActivity : P1 requis -> nouvel essai sans)
    champs = ("id,displayName,givenName,surname,userPrincipalName,mail,createdDateTime,accountEnabled,userType,"
              "assignedLicenses,assignedPlans,lastPasswordChangeDateTime,onPremisesSyncEnabled,externalUserState,"
              "externalUserStateChangeDateTime,passwordPolicies")
    users, err = g.essai(f"users?$select={champs},signInActivity&$top=999")
    connexions_ok = users is not None
    if users is None:
        users, err = g.essai(f"users?$select={champs}&$top=999")
        if users is None:
            sys.exit(f"Lecture des utilisateurs impossible : {err}")

    # MFA : rapport d'enregistrement (P1), sinon methodes par utilisateur (membres actifs, 500 max)
    mfa = {}
    reg, err_mfa = g.essai("reports/authenticationMethods/userRegistrationDetails?$top=999")
    if reg is not None:
        for r in reg:
            meth = [METHODES.get(m, m) for m in r.get("methodsRegistered", [])]
            mfa[r["id"]] = ("Oui" if r.get("isMfaRegistered") else "Non", ", ".join(meth))
    else:
        membres = [u for u in users if u.get("userType") == "Member" and u.get("accountEnabled")]
        if len(membres) <= 500:
            for u in membres:
                m, e = g.essai(f"users/{u['id']}/authentication/methods")
                if m is None:
                    mfa[u["id"]] = ("Inconnu", e)
                    continue
                meth = sorted({TYPES_METHODE.get(x.get("@odata.type"), "") for x in m} - {""})
                mfa[u["id"]] = ("Oui" if set(meth) & FORTES else "Non", ", ".join(meth))
        else:
            err_mfa = f"{err_mfa} ; plus de 500 comptes : MFA non relevée compte par compte"

    # Roles d'administration actifs
    roles_par_user, lignes_roles = {}, []
    defs, _ = g.essai("roleManagement/directory/roleDefinitions?$select=id,displayName")
    nom_role = {d["id"]: d["displayName"] for d in defs or []}
    affect, err_roles = g.essai("roleManagement/directory/roleAssignments?$expand=principal")
    par_id = {u["id"]: u for u in users}
    for a in affect or []:
        role = nom_role.get(a.get("roleDefinitionId"), a.get("roleDefinitionId"))
        p = a.get("principal") or {}
        typ = p.get("@odata.type", "").split(".")[-1]
        u = par_id.get(p.get("id"), {})
        if typ == "user":
            roles_par_user.setdefault(p.get("id"), set()).add(role)
        derniere = dt(((u.get("signInActivity") or {}).get("lastSignInDateTime"))) if u else None
        lignes_roles.append({
            "Role": role, "Membre": p.get("displayName", ""),
            "UPN": p.get("userPrincipalName", "") or p.get("appId", ""),
            "Type": {"user": "Utilisateur", "group": "Groupe", "servicePrincipal": "Application"}.get(typ, typ),
            "Actif": ("Oui" if u.get("accountEnabled") else "Non") if u else "",
            "MFA": mfa.get(p.get("id"), ("", ""))[0] if typ == "user" else "",
            "Methodes MFA": mfa.get(p.get("id"), ("", ""))[1] if typ == "user" else "",
            "Synchronise AD": "Oui" if u.get("onPremisesSyncEnabled") else ("Non" if u else ""),
            "Derniere connexion": fr(derniere) if connexions_ok else NON_P1 if u else "",
            "Portee": a.get("directoryScopeId", "/")})
    lignes_roles.sort(key=lambda l: (l["Role"] != "Global Administrator", l["Role"], l["Membre"]))

    # Comptes (memes colonnes que 12_ + ajouts)
    comptes, invites = [], []
    for u in users:
        lic = sorted({sku_nom.get(l["skuId"], l["skuId"]) for l in u.get("assignedLicenses", [])})
        plans = sorted({plan_nom.get(p["servicePlanId"], p["servicePlanId"]) for p in u.get("assignedPlans", [])
                        if p.get("capabilityStatus") == "Enabled"})
        mdp = dt(u.get("lastPasswordChangeDateTime"))
        si = dt((u.get("signInActivity") or {}).get("lastSignInDateTime"))
        jamais = connexions_ok and si is None
        l = {"GivenName": u.get("givenName") or u.get("displayName", ""), "Surname": u.get("surname", ""),
             "UserPrincipalName": u.get("userPrincipalName", ""), "AccountCreatedDate": fr(dt(u.get("createdDateTime"))),
             "Licences": ", ".join(lic), "LastPasswordChangeDate": fr(mdp),
             "PasswordOlderThan6Months": str(bool(mdp and mdp < SEUIL_6M)) if mdp else "",
             "LastSignInDate": fr(si) if connexions_ok else NON_P1,
             "NeverConnected": str(jamais) if connexions_ok else "",
             "SignInOlderThan6Months": str(jamais or bool(si and si < SEUIL_6M)) if connexions_ok else "",
             "EnabledAppsFromLicences": "; ".join(plans),
             "AccountEnabled": "Oui" if u.get("accountEnabled") else "Non",
             "UserType": "Invité" if u.get("userType") == "Guest" else "Membre",
             "MfaRegistered": mfa.get(u["id"], ("", ""))[0] or ("" if mfa else NON_P1),
             "MfaMethods": mfa.get(u["id"], ("", ""))[1],
             "AdminRoles": ", ".join(sorted(roles_par_user.get(u["id"], []))),
             "OnPremisesSync": "Oui" if u.get("onPremisesSyncEnabled") else "Non",
             "PasswordNeverExpires": "Oui" if "DisablePasswordExpiration" in (u.get("passwordPolicies") or "") else "Non"}
        comptes.append(l)
        if u.get("userType") == "Guest":
            invites.append({"Nom": u.get("displayName", ""), "UPN": u.get("userPrincipalName", ""),
                            "Mail": u.get("mail", ""), "Actif": l["AccountEnabled"], "Cree le": l["AccountCreatedDate"],
                            "Invitation": {"Accepted": "Acceptée", "PendingAcceptance": "En attente"}.get(
                                u.get("externalUserState"), u.get("externalUserState") or ""),
                            "Derniere connexion": l["LastSignInDate"], "Jamais connecte": l["NeverConnected"],
                            "Licences": l["Licences"], "Roles admin": l["AdminRoles"]})

    # Securite du tenant
    sec = []
    def ajout(param, valeur, statut, commentaire=""):
        sec.append({"Parametre": param, "Valeur": valeur, "Statut": statut, "Commentaire": commentaire})
    ajout("Tenant", f"{nom_tenant} ({prefixe})", "Info")
    ajout("Licence Entra ID P1/P2", "Oui" if p1 else "Non", "Info",
          "" if p1 else "Sans P1 : pas d'accès conditionnel ni de date de dernière connexion")
    defaut, e = g.essai("policies/identitySecurityDefaultsEnforcementPolicy", liste=False)
    sd = (defaut or {}).get("isEnabled")
    ca, e_ca = g.essai("identity/conditionalAccess/policies")
    ca_on = [p for p in ca or [] if p.get("state") == "enabled"]
    ca_rapport = [p for p in ca or [] if p.get("state") == "enabledForReportingButNotEnforced"]
    ajout("Paramètres de sécurité par défaut", "Activés" if sd else "Désactivés" if sd is False else e or "",
          "OK" if sd or ca_on else "Critique",
          "" if sd or ca_on else "Ni sécurité par défaut ni accès conditionnel actif : MFA non imposée")
    ajout("Stratégies d'accès conditionnel actives",
          f"{len(ca_on)} (+{len(ca_rapport)} en mode rapport)" if ca is not None else e_ca,
          "Info" if ca is not None else "N/A", ", ".join(p.get("displayName", "") for p in ca_on)[:500])
    ga = [l for l in lignes_roles if l["Role"] == "Global Administrator" and l["Type"] == "Utilisateur"]
    ajout("Administrateurs globaux", len(ga), "OK" if 2 <= len(ga) <= 4 else "Attention",
          "Recommandé : 2 à 4 (dont un compte de secours) ; " + ", ".join(l["UPN"] for l in ga))
    ga_sans = [l["UPN"] for l in lignes_roles if l["Type"] == "Utilisateur" and l["MFA"] == "Non"]
    ajout("Comptes à rôle admin sans MFA enregistrée", len(ga_sans) if mfa else err_mfa,
          ("OK" if not ga_sans else "Critique") if mfa else "N/A", ", ".join(sorted(set(ga_sans))))
    sync = [l["UPN"] for l in lignes_roles if l["Type"] == "Utilisateur" and l["Synchronise AD"] == "Oui"]
    ajout("Comptes à rôle admin synchronisés depuis l'AD", len(sync), "OK" if not sync else "Attention",
          "Un admin cloud doit être un compte cloud dédié : " + ", ".join(sorted(set(sync))))
    auth, e = g.essai("policies/authorizationPolicy", liste=False)
    if isinstance(auth, dict) and "value" in auth and auth["value"]:
        auth = auth["value"][0]
    if auth:
        perm = auth.get("defaultUserRolePermissions", {})
        ajout("Utilisateurs autorisés à créer des applications", "Oui" if perm.get("allowedToCreateApps") else "Non",
              "Attention" if perm.get("allowedToCreateApps") else "OK")
        consent = auth.get("permissionGrantPolicyIdsAssignedToDefaultUserRole", [])
        libre = any("legacy" in c or "user-default" in c for c in consent)
        ajout("Consentement des utilisateurs aux applications", ", ".join(consent) or "Désactivé",
              "Attention" if libre else "OK", "Un utilisateur peut donner accès à ses données à une application tierce"
              if libre else "")
        ajout("Qui peut inviter des invités", auth.get("allowInvitesFrom", ""),
              "Attention" if auth.get("allowInvitesFrom") in ("everyone", "adminsGuestInvitersAndAllMembers") else "OK")
    else:
        ajout("Stratégie d'autorisation", e or "", "N/A")
    jamais_exp = [c["UserPrincipalName"] for c in comptes if c["PasswordNeverExpires"] == "Oui"
                  and c["AccountEnabled"] == "Oui" and c["UserType"] == "Membre" and c["OnPremisesSync"] == "Non"]
    ajout("Comptes cloud dont le mot de passe n'expire jamais", len(jamais_exp), "Info", ", ".join(jamais_exp[:30]))

    # Appareils + LAPS Entra ID
    dev, e_dev = g.essai("devices?$select=id,deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,"
                         "approximateLastSignInDateTime,isCompliant,isManaged,accountEnabled&$top=999")
    laps, e_laps = g.essai("directory/deviceLocalCredentials")
    laps_par = {x.get("deviceName", "").lower(): x for x in laps or []}
    pol, _ = g.essai("policies/deviceRegistrationPolicy", "beta", liste=False)
    laps_actif = ((pol or {}).get("localAdminPassword") or {}).get("isEnabled")
    ajout("LAPS Entra ID activé (stratégie d'inscription des appareils)",
          "Oui" if laps_actif else "Non" if laps_actif is False else "Inconnu",
          "OK" if laps_actif else "Attention" if laps_actif is False else "N/A",
          f"{len(laps or [])} appareil(s) avec mot de passe administrateur local sauvegardé" if laps is not None
          else (e_laps or ""))
    appareils = []
    for d in dev or []:
        lx = laps_par.get((d.get("displayName") or "").lower())
        win = (d.get("operatingSystem") or "").lower().startswith("windows")
        appareils.append({
            "Appareil": d.get("displayName", ""), "OS": d.get("operatingSystem", ""),
            "Version": d.get("operatingSystemVersion", ""),
            "Jonction": {"AzureAd": "Joint Entra ID", "ServerAd": "Hybride (AD + Entra)",
                         "Workplace": "Enregistré (perso)"}.get(d.get("trustType"), d.get("trustType") or ""),
            "Actif": "Oui" if d.get("accountEnabled") else "Non",
            "Derniere connexion": fr(dt(d.get("approximateLastSignInDateTime"))),
            "Conforme": {True: "Oui", False: "Non"}.get(d.get("isCompliant"), ""),
            "Gere (Intune)": {True: "Oui", False: "Non"}.get(d.get("isManaged"), ""),
            "LAPS sauvegarde": ("Oui" if lx else "Non (LAPS AD possible)" if d.get("trustType") == "ServerAd" else "Non")
                               if (win and laps is not None) else "",
            "LAPS derniere sauvegarde": fr(dt((lx or {}).get("lastBackupDateTime"))),
            "LAPS prochaine rotation": fr(dt((lx or {}).get("refreshDateTime")))})

    # Ecriture + analyse des protections Entra ID / Intune
    os.makedirs(sortie, exist_ok=True)
    b = os.path.join(sortie, prefixe)
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import Audit_M365_Securite as secu
        resume_secu = secu.auditer(g, ecrire, b, appareils, dev, nom_role, bool(sd), laps_actif,
                                   len(laps) if laps is not None else None)
    except Exception as e:   # l'audit des comptes reste exploitable meme si l'analyse echoue
        resume_secu = f"analyse Entra / Intune en erreur : {e}"
    ecrire(f"{b}_Audit_Comptes_365.csv", list(comptes[0].keys()) if comptes else ["UserPrincipalName"], comptes)
    ecrire(f"{b}_Audit_M365_Roles.csv", ["Role", "Membre", "UPN", "Type", "Actif", "MFA", "Methodes MFA",
                                         "Synchronise AD", "Derniere connexion", "Portee"], lignes_roles)
    ecrire(f"{b}_Audit_M365_Invites.csv", ["Nom", "UPN", "Mail", "Actif", "Cree le", "Invitation",
                                           "Derniere connexion", "Jamais connecte", "Licences", "Roles admin"], invites)
    ecrire(f"{b}_Audit_M365_Securite.csv", ["Parametre", "Valeur", "Statut", "Commentaire"], sec)
    ecrire(f"{b}_Audit_M365_Appareils.csv", ["Appareil", "OS", "Version", "Jonction", "Actif", "Derniere connexion",
                                             "Conforme", "Gere (Intune)", "LAPS sauvegarde",
                                             "LAPS derniere sauvegarde", "LAPS prochaine rotation", "Intune",
                                             "Chiffre (BitLocker)", "Cle BitLocker Entra", "Conformite Intune",
                                             "Derniere synchro Intune"], appareils)
    print(f"M365 {nom_tenant} : {len(comptes)} comptes ({len(invites)} invités), {len(lignes_roles)} rôle(s) admin, "
          f"{len(appareils)} appareil(s) ; MFA : {'OK' if mfa else err_mfa} ; "
          f"dernières connexions : {'OK' if connexions_ok else NON_P1}\n  {resume_secu}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tenant", required=True, help="domaine du tenant (client.onmicrosoft.com ou domaine verifie)")
    ap.add_argument("--sortie", required=True)
    ap.add_argument("--prefixe", default="")
    a = ap.parse_args()
    prefixe = a.prefixe or a.tenant.split(".")[0]
    collecter(Graph(connexion(a.tenant)), prefixe, a.sortie)


if __name__ == "__main__":
    main()
