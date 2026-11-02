# Audit_M365_Securite.py
# Version      : 1.0
# Derniere modif : Creation - analyse du CONTENU des protections Entra ID / Intune (les noms des strategies ne
#                  sont pas fiables) : acces conditionnel, methodes d'authentification, Intune (catalogue de
#                  parametres, profils, modeles d'administration, securite du point de terminaison, conformite),
#                  appareils geres, cles BitLocker. Module importe par Audit_M365.py (lecture seule).
# Sorties      : <prefixe>_Audit_M365_AccesConditionnel.csv, _Audit_M365_Intune.csv, _Audit_M365_Referentiel.csv
#                + colonnes Intune / BitLocker dans _Audit_M365_Appareils.csv (via enrichir_appareils)
# ============================================================
import json
import re
from datetime import datetime, timedelta, timezone

GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"    # modele de role Administrateur general
ROLES_ADMIN = {GLOBAL_ADMIN, "194ae4cb-b126-40b2-bd5b-6091b380977d", "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
               "29232cdf-9323-42fd-ade2-1d097af3e4de", "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
               "729827e3-9c14-49f7-bb1b-9608f156bbb8", "b0f54661-2d74-4c50-afa3-1ec803f12efe",
               "fe930be7-5e62-47db-91af-98c3a49a38b1", "c4e39bd9-1100-46d3-8c65-fb160da0071f",
               "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", "158c047a-c907-4556-b7ef-446551a6b5f7",
               "966707d0-3269-4727-9be2-8c3a10f19b9d", "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
               "e8611ab8-c189-46e8-94e1-60213ab1f814", "3a2c62db-5318-420d-8d74-23affee5d9d5"}
AUJ = datetime.now(timezone.utc)

# Themes Intune : expressions recherchees dans les identifiants de parametres (catalogue, profils, modeles
# d'administration, modeles de securite) - le nom de la strategie n'est jamais utilise.
THEMES = [
    ("BitLocker", 3, r"bitlocker|requiredeviceencryption|fve_|encryptdevice|storagerequireencryption"),
    ("LAPS", 3, r"(^|[_.])laps|localadminpassword|lapspolicy"),
    ("Antivirus Defender (temps reel)", 3, r"defender_?allowrealtimemonitoring|realtimeprotection|defenderrequirerealtime|"
                                          r"defendermonitorfileactivity|antivirus"),
    ("Reduction de la surface d'attaque (ASR)", 2, r"attacksurfacereduction|asrrules|defenderattacksurfacereduction"),
    ("Pare-feu Windows", 2, r"firewall"),
    ("Autorun / Autoplay desactive", 2, r"autoplay|autorun"),
    ("Windows Update (anneaux / correctifs)", 2, r"windowsupdateforbusiness|qualityupdatesdeferral|deferqualityupdates|"
                                                r"update_allowautoupdate|windowsupdate|windowsqualityupdate"),
    ("Credential Guard / protection LSA", 2, r"deviceguard_lsacfgflags|credentialguard|configurelsaprotectedprocess|"
                                            r"lsacfgflags|runasppl"),
    ("SmartScreen", 1, r"smartscreen"),
    ("Stockage amovible (USB)", 1, r"removablestorage|removable_?disk|deviceinstallation_prevent|usbblock"),
    ("Windows Hello / mot de passe", 1, r"passportforwork|windowshello|devicelock_|passwordrequired|passwordminimumlength"),
]
VALEUR_OFF = re.compile(r"(_0|_false|_disabled|_off|_notconfigured|_audit|_not_configured)$|^(false|0|notconfigured|"
                        r"disabled|userdefined|none|)$", re.I)


def actif(v):
    """Un parametre est considere actif si sa valeur n'est pas explicitement desactivee / non configuree."""
    if v is None:
        return False
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    s = str(v).strip().lower()
    return not VALEUR_OFF.search(s)


def aplatir(obj, prefixe=""):
    """Paires (identifiant, valeur) de tout un objet JSON (profils classiques, conformite)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.startswith("@") or k in ("id", "displayName", "description", "createdDateTime", "lastModifiedDateTime",
                                          "version", "roleScopeTagIds", "supportsScopeTags"):
                continue
            yield from aplatir(v, f"{prefixe}.{k}" if prefixe else k)
    elif isinstance(obj, list):
        for x in obj:
            yield from aplatir(x, prefixe)
    else:
        yield prefixe.lower(), obj


def parametres_catalogue(inst):
    """Paires (settingDefinitionId, valeur) d'un parametre du catalogue (avec enfants)."""
    if not isinstance(inst, dict):
        return
    did = (inst.get("settingDefinitionId") or "").lower()
    for cle in ("choiceSettingValue", "simpleSettingValue"):
        val = inst.get(cle)
        if isinstance(val, dict):
            yield did, val.get("value")
            for enfant in val.get("children") or []:
                yield from parametres_catalogue(enfant)
    for cle in ("groupSettingCollectionValue", "choiceSettingCollectionValue", "simpleSettingCollectionValue"):
        for val in inst.get(cle) or []:
            if isinstance(val, dict):
                if "value" in val:
                    yield did, val.get("value")
                for enfant in val.get("children") or []:
                    yield from parametres_catalogue(enfant)
                if "choiceSettingValue" in val or "settingDefinitionId" in val:
                    yield from parametres_catalogue(val)
    if inst.get("settingInstance"):
        yield from parametres_catalogue(inst["settingInstance"])


def themes_de(paires):
    """Themes couverts par une liste de paires (identifiant, valeur) : {theme: [identifiants actifs]}."""
    res = {}
    for ident, val in paires:
        texte = f"{ident} {val if isinstance(val, str) else ''}".lower()
        for nom, _, motif in THEMES:
            if re.search(motif, texte) and actif(val):
                res.setdefault(nom, []).append(ident.split(".")[-1][-60:])
    return res


def nb_regles_asr(paires):
    """Nombre de regles ASR en mode blocage (catalogue, profil Endpoint Protection, modeles de securite)."""
    n = set()
    for ident, val in paires:
        v = str(val).lower()
        if "attacksurfacereductionrules_" in ident and v.endswith("_block"):
            n.add(ident)
        elif ident.startswith("windows10endpointprotectionconfiguration.defender") and v == "block":
            n.add(ident)
        elif "attacksurfacereduction" in ident and v in ("1", "block", '"block"'):
            n.add(ident)
    return len(n)


# ─── ACCES CONDITIONNEL ─────────────────────────────────────
def analyser_ca(politiques, noms_roles):
    lignes, couvert = [], {}
    for p in politiques or []:
        etat = {"enabled": "Activée", "enabledForReportingButNotEnforced": "Mode rapport", "disabled": "Désactivée"}.get(
            p.get("state"), p.get("state", ""))
        c = p.get("conditions") or {}
        u = c.get("users") or {}
        a = c.get("applications") or {}
        g = p.get("grantControls") or {}
        s = p.get("sessionControls") or {}
        ctl = {x.lower() for x in g.get("builtInControls") or []}
        force = (g.get("authenticationStrength") or {}).get("displayName")
        tous = "All" in (u.get("includeUsers") or [])
        roles = set(u.get("includeRoles") or [])
        apps_tout = bool({"All", "Office365"} & set(a.get("includeApplications") or []))
        mfa = "mfa" in ctl or bool(force)
        bloc = "block" in ctl
        heritage = bool({"exchangeActiveSync", "other"} & set(c.get("clientAppTypes") or [])) and bloc
        conforme = bool({"compliantdevice", "domainjoineddevice"} & ctl)
        risque = bool(c.get("signInRiskLevels") or c.get("userRiskLevels"))
        excl = (u.get("excludeUsers") or []) + (u.get("excludeGroups") or []) + (u.get("excludeRoles") or [])
        tags = []
        if mfa and tous and apps_tout:
            tags.append("MFA pour tous")
        if mfa and (tous or (roles & ROLES_ADMIN) or GLOBAL_ADMIN in roles):
            tags.append("MFA administrateurs")
        if heritage:
            tags.append("Blocage authentification héritée")
        if conforme:
            tags.append("Appareil conforme / joint exigé")
        if risque:
            tags.append("Risque de connexion / utilisateur")
        if bloc and c.get("locations"):
            tags.append("Blocage par localisation")
        if p.get("state") == "enabled":
            for t in tags:
                couvert.setdefault(t, []).append(p.get("displayName", ""))
        elif p.get("state") == "enabledForReportingButNotEnforced":
            for t in tags:
                couvert.setdefault(t + " (rapport)", []).append(p.get("displayName", ""))
        alerte = []
        if p.get("state") == "enabled" and len(excl) > 3:
            alerte.append(f"{len(excl)} exclusions (comptes de secours attendus : 1 ou 2)")
        if p.get("state") == "enabled" and not (ctl or force or s):
            alerte.append("Aucun contrôle d'accès")
        conds = []
        if c.get("platforms"):
            conds.append("Plateformes : " + ", ".join(c["platforms"].get("includePlatforms") or []))
        if c.get("locations"):
            conds.append("Lieux : " + ", ".join(c["locations"].get("includeLocations") or []))
        if c.get("clientAppTypes") and c["clientAppTypes"] != ["all"]:
            conds.append("Clients : " + ", ".join(c["clientAppTypes"]))
        if risque:
            conds.append("Risque : " + ", ".join((c.get("signInRiskLevels") or []) + (c.get("userRiskLevels") or [])))
        lignes.append({
            "Strategie": p.get("displayName", ""), "Etat": etat,
            "Utilisateurs inclus": "Tous" if tous else ", ".join(
                [noms_roles.get(r, r) for r in roles] + (u.get("includeGroups") or []) + (u.get("includeUsers") or []))[:300],
            "Exclusions": len(excl),
            "Applications": "Toutes" if "All" in (a.get("includeApplications") or []) else
                            ", ".join(a.get("includeApplications") or [])[:200],
            "Conditions": " | ".join(conds),
            "Controles": ", ".join(sorted(ctl) + ([f"force : {force}"] if force else [])) + (f" ({g.get('operator')})" if len(ctl) > 1 else ""),
            "Session": ", ".join(k for k, v in s.items() if v and not k.startswith("@")),
            "Couvre": ", ".join(tags), "Alerte": " | ".join(alerte)})
    return lignes, couvert


# ─── INTUNE ─────────────────────────────────────────────────
def collecter_intune(g):
    """Toutes les strategies Intune avec leurs paires (identifiant, valeur) et leur attribution."""
    pols, erreurs = [], []
    # 1. Catalogue de parametres (beta)
    cat, e = g.essai("deviceManagement/configurationPolicies?$select=id,name,platforms,technologies,lastModifiedDateTime",
                     "beta")
    if cat is None:
        erreurs.append(f"Catalogue de paramètres : {e}")
    for p in cat or []:
        st, _ = g.essai(f"deviceManagement/configurationPolicies/{p['id']}/settings?$top=1000", "beta")
        at, _ = g.essai(f"deviceManagement/configurationPolicies/{p['id']}/assignments", "beta")
        paires = [x for s in st or [] for x in parametres_catalogue(s)]
        pols.append({"nom": p.get("name", ""), "type": "Catalogue de paramètres", "plateforme": p.get("platforms", ""),
                     "paires": paires, "attributions": len(at or []), "modif": p.get("lastModifiedDateTime", "")})
    # 2. Profils de configuration classiques (v1.0)
    conf, e = g.essai("deviceManagement/deviceConfigurations")
    if conf is None:
        erreurs.append(f"Profils de configuration : {e}")
    for p in conf or []:
        at, _ = g.essai(f"deviceManagement/deviceConfigurations/{p['id']}/assignments")
        typ = p.get("@odata.type", "").split(".")[-1]
        pols.append({"nom": p.get("displayName", ""), "type": f"Profil ({typ})", "plateforme": typ,
                     "paires": [(f"{typ}.{k}".lower(), v) for k, v in aplatir(p)], "attributions": len(at or []),
                     "modif": p.get("lastModifiedDateTime", "")})
    # 3. Modeles d'administration (ADMX dans Intune, beta)
    adm, _ = g.essai("deviceManagement/groupPolicyConfigurations", "beta")
    for p in adm or []:
        dv, _ = g.essai(f"deviceManagement/groupPolicyConfigurations/{p['id']}/definitionValues?$expand=definition", "beta")
        at, _ = g.essai(f"deviceManagement/groupPolicyConfigurations/{p['id']}/assignments", "beta")
        paires = []
        for d in dv or []:
            df = d.get("definition") or {}
            ident = re.sub(r"\W+", "_", f"{df.get('categoryPath', '')}_{df.get('displayName', '')}").lower()
            paires.append((ident, bool(d.get("enabled"))))
        pols.append({"nom": p.get("displayName", ""), "type": "Modèle d'administration", "plateforme": "windows10",
                     "paires": paires, "attributions": len(at or []), "modif": p.get("lastModifiedDateTime", "")})
    # 4. Securite du point de terminaison - modeles historiques (intents, beta)
    ints, _ = g.essai("deviceManagement/intents", "beta")
    for p in ints or []:
        st, _ = g.essai(f"deviceManagement/intents/{p['id']}/settings", "beta")
        at, _ = g.essai(f"deviceManagement/intents/{p['id']}/assignments", "beta")
        paires = []
        for s in st or []:
            try:
                v = json.loads(s.get("valueJson") or "null")
            except ValueError:
                v = s.get("valueJson")
            paires.append(((s.get("definitionId") or "").lower(), v))
        pols.append({"nom": p.get("displayName", ""), "type": "Sécurité du point de terminaison", "plateforme": "windows10",
                     "paires": paires, "attributions": len(at or []) or (1 if p.get("isAssigned") else 0),
                     "modif": p.get("lastModifiedDateTime", "")})
    # 5. Conformite (v1.0)
    comp, e = g.essai("deviceManagement/deviceCompliancePolicies")
    if comp is None:
        erreurs.append(f"Stratégies de conformité : {e}")
    for p in comp or []:
        at, _ = g.essai(f"deviceManagement/deviceCompliancePolicies/{p['id']}/assignments")
        typ = p.get("@odata.type", "").split(".")[-1]
        pols.append({"nom": p.get("displayName", ""), "type": f"Conformité ({typ})", "plateforme": typ,
                     "paires": [(f"{typ}.{k}".lower(), v) for k, v in aplatir(p)], "attributions": len(at or []),
                     "modif": p.get("lastModifiedDateTime", ""), "conformite": True})
    return pols, erreurs


def analyser_intune(pols):
    lignes, couverture = [], {}
    for p in pols:
        th = themes_de(p["paires"])
        asr = nb_regles_asr(p["paires"])
        if asr:
            th.setdefault("Reduction de la surface d'attaque (ASR)", []).append(f"{asr} règle(s) en blocage")
        for t in th:
            couverture.setdefault(t, []).append(p)
        cles = sorted({i for v in th.values() for i in v})
        lignes.append({"Strategie": p["nom"], "Type": p["type"], "Plateforme": p["plateforme"],
                       "Attribuee": "Oui" if p["attributions"] else "Non",
                       "Themes de securite": ", ".join(sorted(th)), "Parametres actifs": len(
                           [1 for _, v in p["paires"] if actif(v)]),
                       "Exemples de parametres": ", ".join(cles[:8]), "Modifiee le": (p.get("modif") or "")[:10]})
    return lignes, couverture


# ─── REFERENTIEL ENTRA / INTUNE ─────────────────────────────
def referentiel(sd_actif, couvert_ca, err_ca, methodes, pols, couverture, err_intune, appareils_mdm, cles_bl,
                laps_entra, nb_laps):
    ref = []

    def r(dom, ctrl, statut, detail, crit, reco):
        ref.append({"Domaine": dom, "Controle": ctrl, "Statut": statut, "Detail": detail, "Criticite": crit,
                    "Recommandation": reco})

    def ca(tag, ctrl, crit, reco, sd_suffit=False):
        if couvert_ca.get(tag):
            r("Entra ID", ctrl, "En place", "Accès conditionnel : " + ", ".join(couvert_ca[tag]), crit, reco)
        elif sd_suffit and sd_actif:
            r("Entra ID", ctrl, "En place", "Paramètres de sécurité par défaut activés", crit, reco)
        elif couvert_ca.get(tag + " (rapport)"):
            r("Entra ID", ctrl, "Partiel", "Seulement en mode rapport : " + ", ".join(couvert_ca[tag + " (rapport)"]),
              crit, reco)
        elif err_ca and "licence" in err_ca.lower():
            if "P2" in ctrl:
                r("Entra ID", ctrl, "Non applicable", "Licence Entra ID P2 requise", crit, reco)
            else:
                r("Entra ID", ctrl, "Absent", "Pas d'accès conditionnel (licence Entra ID P1 absente)"
                  + (" et sécurité par défaut désactivée" if sd_suffit else ""), crit, reco)
        elif err_ca and not sd_actif:
            r("Entra ID", ctrl, "Non vérifiable", err_ca, crit, reco)
        else:
            r("Entra ID", ctrl, "Absent", "Aucune stratégie ne couvre ce contrôle", crit, reco)

    ca("MFA pour tous", "MFA imposée à tous les utilisateurs", 3,
       "Stratégie d'accès conditionnel : tous les utilisateurs, toutes les applications, MFA (ou sécurité par défaut).",
       sd_suffit=True)
    ca("MFA administrateurs", "MFA imposée aux administrateurs", 3,
       "Stratégie dédiée aux rôles d'administration avec une force d'authentification résistante au hameçonnage.",
       sd_suffit=True)
    ca("Blocage authentification héritée", "Authentification héritée bloquée (POP, IMAP, SMTP AUTH...)", 3,
       "Bloquer les protocoles d'authentification hérités, qui contournent la MFA.", sd_suffit=True)
    ca("Appareil conforme / joint exigé", "Accès réservé aux appareils conformes ou joints", 2,
       "Exiger un appareil conforme Intune ou joint (hybride) pour l'accès aux données.")
    ca("Risque de connexion / utilisateur", "Réaction aux connexions à risque (Entra ID P2)", 1,
       "Avec Entra ID P2 : exiger la MFA / le changement de mot de passe sur risque moyen et élevé.")
    faibles = [m for m in methodes if m in ("Sms", "Voice", "Email")]
    if methodes:
        r("Entra ID", "Méthodes d'authentification faibles désactivées", "En place" if not faibles else "Partiel",
          ("Actives : " + ", ".join(methodes)), 2,
          "Privilégier Authenticator / clés FIDO2 et désactiver SMS et appel vocal pour la MFA.")
    r("Entra ID", "LAPS Entra ID", "En place" if laps_entra else "Absent" if laps_entra is False else "Non vérifiable",
      f"{nb_laps} appareil(s) avec mot de passe administrateur local sauvegardé" if nb_laps is not None else "", 3,
      "Activer Windows LAPS dans les paramètres des appareils Entra ID et le déployer par Intune.")

    for nom, crit, _ in THEMES:
        pp = couverture.get(nom, [])
        att = [p for p in pp if p["attributions"]]
        if err_intune and not pols:
            st, det = "Non vérifiable", "Intune non disponible : " + " ; ".join(err_intune)[:250]
        elif att:
            st, det = "En place", ", ".join(f"{p['nom']} ({p['type']})" for p in att)[:400]
            if all(p.get("conformite") for p in att):
                st, det = "Partiel", "Seulement exigé en conformité (pas de configuration déployée) : " + det
        elif pp:
            st, det = "Configuré mais non attribué", ", ".join(p["nom"] for p in pp)[:400]
        else:
            st, det = "Absent", "Aucune stratégie Intune ne configure ce thème"
        r("Intune", nom, st, det, crit, f"Déployer une stratégie Intune « {nom} » attribuée aux appareils Windows.")

    win = [d for d in appareils_mdm if (d.get("operatingSystem") or "").lower() == "windows"]
    if win:
        chif = [d for d in win if d.get("isEncrypted")]
        p = round(100 * len(chif) / len(win))
        r("Intune", "Postes Windows chiffrés (BitLocker)", "En place" if p >= 95 else "Partiel" if chif else "Absent",
          f"{len(chif)} / {len(win)} ({p} %) ; clés BitLocker dans Entra ID : {len(cles_bl) if cles_bl is not None else 'non lisible'}",
          3, "Chiffrer tous les postes et sauvegarder les clés de récupération dans Entra ID.")
        nc = [d for d in win if d.get("complianceState") not in ("compliant",)]
        r("Intune", "Postes Windows conformes", "En place" if not nc else "Partiel",
          f"{len(win) - len(nc)} / {len(win)} conformes", 2, "Traiter les appareils non conformes.")
    return ref


def enrichir_appareils(appareils, devices_entra, appareils_mdm, cles_bl):
    par_aad = {(d.get("azureADDeviceId") or "").lower(): d for d in appareils_mdm}
    id_entra = {(d.get("displayName") or "").lower(): (d.get("deviceId") or "").lower() for d in devices_entra or []}
    for a in appareils:
        did = id_entra.get(a["Appareil"].lower(), "")
        m = par_aad.get(did)
        a["Intune"] = "Oui" if m else "Non"
        a["Chiffre (BitLocker)"] = {True: "Oui", False: "Non"}.get((m or {}).get("isEncrypted"), "")
        a["Conformite Intune"] = (m or {}).get("complianceState", "")
        a["Derniere synchro Intune"] = ((m or {}).get("lastSyncDateTime") or "")[:10]
        a["Cle BitLocker Entra"] = ("Oui" if did in (cles_bl or set()) else "Non") if cles_bl is not None and \
            a["OS"].lower().startswith("windows") else ""
    return appareils


def auditer(g, ecrire, base, appareils, devices_entra, noms_roles, sd_actif, laps_entra, nb_laps):
    """Point d'entree appele par Audit_M365.py ; renvoie un resume texte."""
    ca_pol, err_ca = g.essai("identity/conditionalAccess/policies")
    lignes_ca, couvert = analyser_ca(ca_pol, noms_roles)
    amp, _ = g.essai("policies/authenticationMethodsPolicy", liste=False)
    methodes = [c.get("id") for c in (amp or {}).get("authenticationMethodConfigurations", []) if c.get("state") == "enabled"]
    pols, err_int = collecter_intune(g)
    lignes_int, couverture = analyser_intune(pols)
    mdm, e_mdm = g.essai("deviceManagement/managedDevices?$select=deviceName,operatingSystem,osVersion,complianceState,"
                         "isEncrypted,lastSyncDateTime,azureADDeviceId,managedDeviceOwnerType")
    bl, e_bl = g.essai("informationProtection/bitlocker/recoveryKeys?$select=id,deviceId")
    cles = {(k.get("deviceId") or "").lower() for k in bl} if bl is not None else None
    ref = referentiel(sd_actif, couvert, err_ca, methodes, pols, couverture, err_int, mdm or [], cles, laps_entra, nb_laps)
    enrichir_appareils(appareils, devices_entra, mdm or [], cles)
    ecrire(f"{base}_Audit_M365_AccesConditionnel.csv", ["Strategie", "Etat", "Utilisateurs inclus", "Exclusions",
                                                        "Applications", "Conditions", "Controles", "Session", "Couvre",
                                                        "Alerte"], lignes_ca)
    ecrire(f"{base}_Audit_M365_Intune.csv", ["Strategie", "Type", "Plateforme", "Attribuee", "Themes de securite",
                                             "Parametres actifs", "Exemples de parametres", "Modifiee le"], lignes_int)
    ecrire(f"{base}_Audit_M365_Referentiel.csv", ["Domaine", "Controle", "Statut", "Detail", "Criticite",
                                                  "Recommandation"], ref)
    ok = sum(1 for x in ref if x["Statut"] == "En place")
    return (f"accès conditionnel : {len(lignes_ca) if ca_pol is not None else err_ca} stratégie(s) ; Intune : "
            f"{len(pols)} stratégie(s){' (' + '; '.join(err_int)[:80] + ')' if err_int and not pols else ''} ; "
            f"référentiel : {ok} / {len(ref)} en place")
