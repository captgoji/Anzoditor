#!/usr/bin/env python3
# Audit_UniFi.py
# Version      : 1.0
# Derniere modif : Creation - audit d'un controleur UniFi Network (API, lecture seule)
# Role         : Lit la configuration d'un controleur UniFi (UniFi OS : UDM, Cloud Key, UniFi OS Server ;
#                ou controleur "classique" sur le port 8443) et ecrit dans --sortie (Temp_CSV/RESEAU),
#                avec le meme format que Audit_Reseau_SNMP.py (meme classeur Excel/Audit_Reseau.xlsx) :
#                  <ctrl>_Audit_Reseau.csv           1 ligne par equipement UniFi (switch, borne, passerelle)
#                  <ctrl>_Audit_Reseau_Ports.csv     1 ligne par port de switch : profil, mode Access / Trunk,
#                                                    VLAN natif, VLANs tagues, PoE, voisin
#                  <ctrl>_Audit_Reseau_VLAN.csv      reseaux / VLAN crees : nom, ID, sous-reseau, DHCP, isolation
#                  <ctrl>_Audit_Reseau_Wifi.csv      SSID : securite, VLAN, invite isole, PMF, masque
#                  <ctrl>_Audit_Reseau_Voisins.csv   liaisons entre equipements (uplinks) et LLDP
#                  <ctrl>_Audit_Reseau_Controles.csv points de controle evalues automatiquement
# Usage        : lance par ansible/audit.yml (section [unifi] du .ini), ou a la main :
#                UNIFI_USER=audit UNIFI_PASSWORD=xxx python3 Audit_UniFi.py --nom ASB-UNIFI \
#                    --hote 192.168.0.21 [--port 11443] [--site default] --sortie /tmp/out
# Identifiants : variables d'environnement UNIFI_USER / UNIFI_PASSWORD (compte LOCAL du controleur, role
#                "View Only" / lecture seule ; un compte Ubiquiti (UI.com) avec MFA ne peut pas etre utilise).
# Lecture seule : uniquement des GET, plus la connexion et la commande "get-admins" (liste des administrateurs).
#                Les secrets (cles Wi-Fi, mots de passe SSH des appareils, RADIUS) ne sont jamais ecrits.
# TLS          : certificat auto-signe du controleur accepte par defaut (--verifier-tls pour l'exiger).
# Prerequis    : python3 seul (aucun module a installer).
# ============================================================
import argparse
import csv
import http.cookiejar
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta

PORTS_DEFAUT = (443, 11443, 8443)   # UniFi OS (UDM / Cloud Key), UniFi OS Server, controleur classique
TYPES = {"usw": "Switch", "uap": "Borne Wi-Fi", "ugw": "Passerelle", "udm": "Passerelle", "uxg": "Passerelle",
         "uck": "Cloud Key", "ubb": "Pont radio", "uph": "Telephone"}
USAGES = {"corporate": "LAN", "guest": "Invites", "vlan-only": "VLAN seul (sans passerelle UniFi)"}
ETATS = {0: "DECONNECTE du controleur", 1: "OK", 2: "En attente d'adoption", 4: "OK (mise a jour en cours)",
         5: "OK (provisionnement)", 6: "Perte de contact", 7: "Adoption en cours", 9: "Echec d'adoption",
         10: "Isole", 11: "Isole"}
CLES_PORT = ("forward", "native_networkconf_id", "tagged_networkconf_ids", "excluded_networkconf_ids",
             "tagged_vlan_mgmt", "voice_networkconf_id", "poe_mode", "op_mode", "isolation",
             "port_security_enabled", "dot1x_ctrl")


# ─── API ───────────────────────────────────────────────────
class ErreurApi(Exception):
    pass


class Controleur:
    def __init__(self, hote, port, verifier_tls, delai=25):
        self.hote, self.port, self.delai = hote, port, delai
        ctx = ssl.create_default_context() if verifier_tls else ssl._create_unverified_context()
        self.cj = http.cookiejar.CookieJar()
        # ProxyHandler({}) : jamais de proxy (controleur sur le reseau du client, via VPN)
        self.op = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                              urllib.request.HTTPSHandler(context=ctx),
                                              urllib.request.HTTPCookieProcessor(self.cj))
        self.base, self.prefixe, self.csrf, self.genre = "", "", "", ""

    def _req(self, url, donnees=None, entetes=None):
        h = {"Accept": "application/json", "Content-Type": "application/json", **(entetes or {})}
        if self.csrf:
            h["X-CSRF-Token"] = self.csrf
        r = urllib.request.Request(url, data=json.dumps(donnees).encode() if donnees is not None else None,
                                   headers=h, method="POST" if donnees is not None else "GET")
        try:
            with self.op.open(r, timeout=self.delai) as rep:
                corps = rep.read()
                return rep.status, dict(rep.headers), corps
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers or {}), e.read() or b""

    def connecter(self, user, mdp):
        ports = [self.port] if self.port else list(PORTS_DEFAUT)
        essais = []
        for port in ports:
            base = f"https://{self.hote}" + ("" if port == 443 else f":{port}")
            # 1. UniFi OS (UDM, Cloud Key Gen2+, UniFi OS Server)
            try:
                st, h, corps = self._req(base + "/api/auth/login", {"username": user, "password": mdp, "remember": False})
            except Exception as e:     # port ferme, TLS, delai
                essais.append(f"{port} : {getattr(e, 'reason', e)}")
                continue
            if st == 200:
                self.base, self.prefixe, self.genre = base, "/proxy/network", "UniFi OS"
                self.csrf = {k.lower(): v for k, v in h.items()}.get("x-csrf-token", "")
                return
            if st == 499 or b"MFA" in corps or b"2fa" in corps.lower():
                raise ErreurApi("le compte demande une validation MFA : utiliser un compte LOCAL du controleur "
                                "(Parametres > Administrateurs > restreint a l'acces local, role lecture seule)")
            # 2. Controleur classique (Network Application seule : /api/login)
            st2, h2, corps2 = self._req(base + "/api/login", {"username": user, "password": mdp})
            if st2 == 200:
                self.base, self.prefixe, self.genre = base, "", "controleur classique"
                return
            essais.append(f"{port} : UniFi OS HTTP {st}, classique HTTP {st2}")
            if (st in (401, 403) and re.search(rb"AUTHENTICATION|INVALID|CREDENTIAL", corps.upper())) or \
                    (st2 in (400, 401, 403) and b"api.err.Invalid" in corps2):
                raise ErreurApi(f"identifiants refuses par {base} (compte local du controleur ? {essais[-1]})")
        raise ErreurApi("controleur introuvable ou connexion refusee : " + " ; ".join(essais))

    def api(self, chemin, donnees=None, optionnel=False):
        st, _, corps = self._req(f"{self.base}{self.prefixe}{chemin}", donnees)
        if st != 200:
            if optionnel:
                return []
            raise ErreurApi(f"{chemin} : HTTP {st} {corps[:200]!r}")
        try:
            j = json.loads(corps or b"{}")
        except ValueError:
            if optionnel:
                return []
            raise ErreurApi(f"{chemin} : reponse non JSON")
        if isinstance(j, dict) and j.get("meta", {}).get("rc") not in (None, "ok"):
            if optionnel:
                return []
            raise ErreurApi(f"{chemin} : {j['meta'].get('msg')}")
        return j.get("data", j) if isinstance(j, dict) else j

    def deconnecter(self):
        try:
            self._req(self.base + ("/api/auth/logout" if self.prefixe else "/api/logout"), {})
        except Exception:
            pass


# ─── Outils ────────────────────────────────────────────────
def ecrire(chemin, entetes, lignes):
    with open(chemin, "w", encoding="utf-8-sig", newline="") as f:
        wr = csv.DictWriter(f, fieldnames=entetes, delimiter=";", quoting=csv.QUOTE_ALL, extrasaction="ignore")
        wr.writeheader()
        for l in lignes:
            wr.writerow(l)


def plages(vlans):
    n = sorted({int(x) for x in vlans if str(x).isdigit()})
    out, i = [], 0
    while i < len(n):
        j = i
        while j + 1 < len(n) and n[j + 1] == n[j] + 1:
            j += 1
        out.append(str(n[i]) if i == j else f"{n[i]}-{n[j]}")
        i = j + 1
    return ", ".join(out)


def duree(s):
    try:
        s = int(s)
    except (TypeError, ValueError):
        return "", None
    j, r = divmod(s, 86400)
    return f"{j} j {r // 3600} h", j


def oui(b):
    return "Oui" if b else "Non"


# ─── Reseaux / VLAN ────────────────────────────────────────
def analyser_reseaux(nets):
    """Reseaux locaux (LAN / invites / VLAN seul) -> {id: {vlan, nom, ...}}. VLAN 1 = reseau par defaut non tague."""
    res = {}
    for n in nets:
        if n.get("purpose") not in USAGES:
            continue
        v = str(n.get("vlan") or "").strip()
        tague = v.isdigit() and n.get("vlan_enabled", True) is not False and v != "1"
        res[n["_id"]] = {"vlan": int(v) if tague else 1, "nom": n.get("name", ""), "net": n,
                         "defaut": not tague}
    return res


def libelle_vlan(info):
    return f"{info['vlan']} ({info['nom']})" if info else ""


# ─── Ports ─────────────────────────────────────────────────
def config_port(port, surcharge, profils):
    """Configuration effective d'un port : valeurs du port, puis du profil, puis de la surcharge du port
    (sauf surcharge en mode "auto" = le profil s'applique)."""
    pid = (surcharge or {}).get("portconf_id") or port.get("portconf_id") or ""
    prof = profils.get(pid, {})
    eff = {k: port[k] for k in CLES_PORT if k in port}
    eff.update({k: prof[k] for k in CLES_PORT if k in prof})
    if surcharge and not (surcharge.get("setting_preference") == "auto" and prof):
        eff.update({k: surcharge[k] for k in CLES_PORT if k in surcharge})
    perso = bool(surcharge) and surcharge.get("setting_preference") != "auto" and \
        any(k in surcharge for k in ("forward", "native_networkconf_id", "tagged_vlan_mgmt",
                                     "excluded_networkconf_ids", "tagged_networkconf_ids"))
    if perso:
        nom_profil = "Personnalise" + (f" (sur {prof['name']})" if prof.get("name") and
                                       (surcharge or {}).get("portconf_id") else "")
    else:
        nom_profil = prof.get("name") or "Par defaut (All)"
    return eff, nom_profil


def vlans_port(eff, reseaux):
    """-> (mode, natif, tagues[ids reseaux])"""
    if eff.get("op_mode") == "mirror":
        return "Miroir", None, []
    fwd = eff.get("forward") or ("customize" if "tagged_vlan_mgmt" in eff else "all")
    if fwd == "disabled":
        return "Desactive", None, []
    defaut = next((i for i, r in reseaux.items() if r["defaut"] and r["net"].get("purpose") == "corporate"), None)
    natif = eff.get("native_networkconf_id")
    if natif is None:
        natif = defaut
    natif = natif or None   # "" = aucun VLAN natif
    tous = [i for i in reseaux if i != natif and not reseaux[i]["defaut"]]
    if fwd == "native":
        tag = []
    elif fwd == "all":
        tag = tous
    else:
        tvm = eff.get("tagged_vlan_mgmt")
        if tvm == "block_all":
            tag = []
        elif tvm == "auto":
            tag = tous
        elif tvm == "custom" or "excluded_networkconf_ids" in eff:
            exclus = set(eff.get("excluded_networkconf_ids") or [])
            tag = [i for i in tous if i not in exclus]
        elif "tagged_networkconf_ids" in eff:
            tag = [i for i in eff.get("tagged_networkconf_ids") or [] if i in reseaux and i != natif]
        else:
            tag = tous
    mode = "Trunk" if tag else ("Access" if natif else "Aucun VLAN")
    if eff.get("op_mode") == "aggregate":
        mode += " (agregat)"
    return mode, natif, tag


# ─── Wi-Fi ─────────────────────────────────────────────────
def securite_wifi(w):
    sec, mode = (w.get("security") or "").lower(), (w.get("wpa_mode") or "").lower()
    if sec == "open":
        return "Ouvert"
    if sec == "wep":
        return "WEP"
    ent = sec in ("wpaeap", "wpa-eap", "eap", "osen")
    if w.get("wpa3_support") and w.get("wpa3_transition"):
        base = "WPA2/WPA3"
    elif w.get("wpa3_support") or mode == "wpa3":
        base = "WPA3"
    elif mode in ("wpa1", "wpa"):
        base = "WPA"
    else:
        base = "WPA2"
    return base + ("-Entreprise" if ent else "")


# ─── Audit d'un site ───────────────────────────────────────
def auditer_site(c, site, nom_ctrl, sortie_lignes):
    s = site["name"]
    lib_site = site.get("desc") or s
    devices = c.api(f"/api/s/{s}/stat/device")
    nets = c.api(f"/api/s/{s}/rest/networkconf")
    profils = {p["_id"]: p for p in c.api(f"/api/s/{s}/rest/portconf", optionnel=True)}
    wlans = c.api(f"/api/s/{s}/rest/wlanconf", optionnel=True)
    reglages = {r.get("key"): r for r in c.api(f"/api/s/{s}/get/setting", optionnel=True)}
    admins = c.api(f"/api/s/{s}/cmd/sitemgr", {"cmd": "get-admins"}, optionnel=True)
    reseaux = analyser_reseaux(nets)
    L = sortie_lignes
    mgmt, snmp, ips = reglages.get("mgmt", {}), reglages.get("snmp", {}), reglages.get("ips", {})
    ssh_actif = bool(mgmt.get("x_ssh_enabled"))
    ssh_mdp = ssh_actif and mgmt.get("x_ssh_auth_password_enabled", True) is not False
    snmp_comm = (snmp.get("community") or "") if snmp.get("enabled") else ""

    noms = {d.get("mac"): d.get("name") or d.get("model") or d.get("mac") for d in devices}
    # Liaisons entre equipements : (mac du switch, port) -> equipement raccorde
    descendants = {}
    for d in devices:
        u = d.get("uplink") or {}
        if u.get("uplink_mac") and u.get("uplink_remote_port") not in (None, ""):
            try:
                descendants[(u["uplink_mac"], int(u["uplink_remote_port"]))] = noms.get(d.get("mac"))
            except (TypeError, ValueError):
                pass
            L["voisins"].append({"Equipement": noms.get(u["uplink_mac"], u["uplink_mac"]),
                                 "Port local": str(u.get("uplink_remote_port")), "Voisin": noms.get(d.get("mac")),
                                 "Port voisin": str(u.get("port_idx") or u.get("name") or ""),
                                 "Description port voisin": "liaison montante (controleur UniFi)",
                                 "Chassis voisin": d.get("mac", "")})

    # --- Reseaux / VLAN
    for i, r in sorted(reseaux.items(), key=lambda x: x[1]["vlan"]):
        n = r["net"]
        plage = f"{n.get('dhcpd_start', '')} - {n.get('dhcpd_stop', '')}".strip(" -")
        dhcp = (f"Oui ({plage})" if plage else "Oui") if n.get("dhcpd_enabled") else ("Relais" if n.get("dhcp_relay_enabled") else "Non")
        alerte = []
        L["vlan"].append({"Controleur": nom_ctrl, "Site": lib_site, "VLAN": r["vlan"], "Nom": r["nom"],
                          "Usage": USAGES[n["purpose"]] + (" (par defaut, non tague)" if r["defaut"] else ""),
                          "Sous-reseau": n.get("ip_subnet", ""), "DHCP": dhcp,
                          "Isolation": oui(n.get("network_isolation_enabled") or n.get("purpose") == "guest"),
                          "Acces Internet": oui(n.get("internet_access_enabled", True)),
                          "IGMP snooping": oui(n.get("igmp_snooping")),
                          "Ports connectes en natif": 0, "Ports connectes tagues": 0, "SSID": "", "Alerte": " | ".join(a for a in alerte if a)})
    vlan_ligne = {l["Nom"]: l for l in L["vlan"] if l["Site"] == lib_site and l["Controleur"] == nom_ctrl}

    # --- Equipements et ports
    for d in devices:
        nom = noms.get(d.get("mac"))
        typ = TYPES.get(d.get("type"), d.get("type") or "Autre")
        up, jours = duree(d.get("uptime"))
        etat = ETATS.get(d.get("state"), f"Etat {d.get('state')}")
        surch = {o.get("port_idx"): o for o in d.get("port_overrides") or []}
        lldp = {}
        for x in d.get("lldp_table") or []:
            lldp.setdefault(x.get("local_port_idx"), []).append(x.get("chassis_descr") or x.get("system_name")
                                                                or x.get("chassis_id", ""))
            L["voisins"].append({"Equipement": nom, "Port local": str(x.get("local_port_idx", "")),
                                 "Voisin": x.get("system_name") or x.get("chassis_descr") or "",
                                 "Port voisin": x.get("port_id", ""), "Description port voisin": x.get("port_descr", ""),
                                 "Chassis voisin": x.get("chassis_id", "")})
        nb, nb_up, nb_inut, vl_eq, all_hors_liaison = 0, 0, 0, set(), []
        for p in sorted(d.get("port_table") or [], key=lambda x: x.get("port_idx") or 0):
            if typ in ("Borne Wi-Fi", "Pont radio", "Telephone") or not p.get("port_idx"):
                continue
            idx = p.get("port_idx")
            eff, nom_prof = config_port(p, surch.get(idx), profils)
            mode, natif, tag = vlans_port(eff, reseaux)
            o = surch.get(idx) or {}
            actif = p.get("enable", True) is not False and mode != "Desactive"
            branche = bool(p.get("up"))
            voisin = descendants.get((d.get("mac"), idx)) or " - ".join(v for v in lldp.get(idx, []) if v)
            liaison = bool(p.get("is_uplink") or descendants.get((d.get("mac"), idx)))
            alerte = []
            if actif and not branche and typ == "Switch":
                alerte.append("Actif mais non connecte")
                nb_inut += 1
            tous_tag = len(tag) > 1 and len(tag) >= sum(1 for r in reseaux.values() if not r["defaut"]) - (1 if natif and not reseaux[natif]["defaut"] else 0)
            if branche and not liaison and not lldp.get(idx) and tous_tag:
                alerte.append("Tous les VLAN tagues sur un port qui n'est pas une liaison connue : verifier l'appareil branche")
                all_hors_liaison.append(f"{nom} port {idx}")
            if natif and reseaux.get(natif, {}).get("net", {}).get("purpose") == "guest" and tag:
                alerte.append("Reseau invite et VLAN internes sur le meme port")
            nb += 1
            nb_up += branche
            if natif:
                vl_eq.add(reseaux[natif]["vlan"])
                ln = vlan_ligne.get(reseaux[natif]["nom"])
                if ln and branche:
                    ln["Ports connectes en natif"] += 1
            for t in tag:
                vl_eq.add(reseaux[t]["vlan"])
                ln = vlan_ligne.get(reseaux[t]["nom"])
                if ln and branche:
                    ln["Ports connectes tagues"] += 1
            poe = ""
            if p.get("port_poe") or p.get("poe_caps"):
                pm = eff.get("poe_mode") or p.get("poe_mode") or ""
                poe = ("Coupe" if pm == "off" else pm or "auto") + \
                      (f" ({float(p['poe_power']):.1f} W)" if p.get("poe_power") not in (None, "", "0", "0.00") else "")
            L["ports"].append({
                "Equipement": nom, "Port": str(idx), "Description": o.get("name") or p.get("name", ""),
                "Alias": "", "Type": (p.get("media") or "Ethernet") + (" (montant)" if p.get("is_uplink") else ""),
                "Admin": "Active" if actif else "Desactive", "Etat": "Connecte" if branche else "Non connecte",
                "Vitesse (Mb/s)": p.get("speed", "") if branche else "", "Mode": mode,
                "VLAN natif": libelle_vlan(reseaux.get(natif)) if natif else ("" if mode == "Desactive" else "Aucun"),
                "VLANs non tagues": str(reseaux[natif]["vlan"]) if natif else "",
                "VLANs tagues": plages(reseaux[t]["vlan"] for t in tag),
                "Reseaux tagues": ", ".join(reseaux[t]["nom"] for t in sorted(tag, key=lambda t: reseaux[t]["vlan"]))[:400],
                "Profil": nom_prof, "PoE": poe,
                "Securite du port": " ".join(x for x in (
                    "802.1X" if eff.get("dot1x_ctrl") not in (None, "", "force_authorized") else "",
                    "MAC limitees" if eff.get("port_security_enabled") else "",
                    "Isole" if eff.get("isolation") else "") if x),
                "Voisin LLDP": voisin, "Alerte": " | ".join(alerte)})
        alertes = []
        if d.get("upgradable"):
            alertes.append(f"Mise a jour firmware disponible ({d.get('upgrade_to_firmware') or 'voir controleur'})")
        if d.get("model_in_eol"):
            alertes.append("Modele en fin de vie (EOL)")
        elif d.get("model_in_lts"):
            alertes.append("Modele en support long terme (LTS) : fin de vie annoncee")
        if etat.startswith(("DECONNECTE", "Perte", "Echec", "Isole")):
            alertes.append(etat)
        if all_hors_liaison:
            alertes.append(f"{len(all_hors_liaison)} port(s) d'acces avec tous les VLAN tagues")
        if snmp_comm.lower() in ("public", "private"):
            alertes.append(f"Communaute SNMP par defaut ({snmp_comm})")
        redem = (datetime.now() - timedelta(days=jours)).strftime("%d/%m/%Y") if jours is not None else ""
        L["eq"].append({
            "Equipement": nom, "IP": d.get("ip", ""), "Type": typ, "Marque": "Ubiquiti",
            "Modele": " ".join(x for x in (d.get("model_name") or d.get("shortname") or "", f"[{d.get('model')}]"
                                           if d.get("model") else "") if x),
            "Firmware": d.get("version", ""), "S/N": d.get("serial") or d.get("mac", "").replace(":", "").upper(),
            "Nom SNMP": "", "Description": f"Controleur UniFi {nom_ctrl} ({c.genre}), MAC {d.get('mac', '')}",
            "Localisation": lib_site, "Contact": "", "Uptime": up, "Dernier redemarrage": redem,
            "Version SNMP": "Controleur UniFi", "Communaute par defaut": snmp_comm if snmp_comm.lower()
            in ("public", "private") else "Non", "Telnet": "Non", "HTTP": "", "HTTPS": "",
            "SSH": ("Oui (mot de passe)" if ssh_mdp else "Oui (cle)") if ssh_actif else "Non",
            "Ports physiques": nb if typ == "Switch" else "", "Ports connectes": nb_up if typ == "Switch" else "",
            "Ports actifs non connectes": nb_inut if typ == "Switch" else "",
            "VLANs": plages(vl_eq), "Voisins LLDP": " - ".join(sorted({v for (m, _), v in descendants.items()
                                                                     if m == d.get("mac") and v})),
            "Firmware a jour": "Non" if d.get("upgradable") else "Oui",
            "Fin de vie": "Oui" if d.get("model_in_eol") else ("LTS" if d.get("model_in_lts") else "Non"),
            "Source": "Controleur UniFi", "Statut": "OK" if etat.startswith("OK") else f"INJOIGNABLE ({etat})",
            "Alerte": " | ".join(alertes)})

    # --- Wi-Fi
    for w in wlans:
        if w.get("name") is None:
            continue
        net = reseaux.get(w.get("networkconf_id"))
        guest = bool(w.get("is_guest")) or (net and net["net"].get("purpose") == "guest")
        isole = guest and bool((net and (net["net"].get("purpose") == "guest"
                                         or net["net"].get("network_isolation_enabled"))) or w.get("l2_isolation"))
        sec = securite_wifi(w)
        alerte = []
        actif_w = w.get("enabled", True) is not False
        if actif_w and sec in ("Ouvert", "WEP", "WPA") and not (sec == "Ouvert" and guest and isole):
            alerte.append(f"Chiffrement faible ({sec})")
        if actif_w and guest and not isole:
            alerte.append("Reseau invite non isole du reseau interne")
        if w.get("enabled", True) and sec.startswith("WPA2") and not sec.startswith("WPA2/") and \
                (w.get("pmf_mode") or "disabled") == "disabled":
            alerte.append("PMF (802.11w) desactive")
        if net:
            ln = vlan_ligne.get(net["nom"])
            if ln:
                ln["SSID"] = ", ".join(x for x in (ln["SSID"], w["name"]) if x)
        comm = [x for x in (
            "desactive" if w.get("enabled") is False else "",
            "masque" if w.get("hide_ssid") else "",
            "filtrage MAC" if w.get("mac_filter_enabled") else "",
            f"PMF {w.get('pmf_mode')}" if w.get("pmf_mode") else "",
            "isolation des clients" if w.get("l2_isolation") else "",
            "portail invite" if guest else "",
            "limite a des groupes de bornes" if w.get("ap_group_ids") and w.get("ap_group_mode") != "all" else "") if x]
        L["wifi"].append({"Equipement": f"{nom_ctrl} ({lib_site})", "SSID": w["name"], "Chiffrement": sec,
                          "Reseau invite isole": ("Oui" if isole else "Non") if guest else "",
                          "VLAN": libelle_vlan(net) if net else "1 (par defaut)",
                          "Actif": oui(w.get("enabled", True)), "Commentaire": ", ".join(comm),
                          "Alerte": " | ".join(alerte)})

    # --- Points de controle
    def ctl(point, res, comm=""):
        L["ctl"].append({"Equipement": f"{nom_ctrl} ({lib_site})", "IP": c.hote, "Type": "Controleur UniFi",
                         "Point de controle": point, "Resultat": res, "Commentaire": comm[:500]})
    a_jour = [f"{noms.get(d.get('mac'))} ({d.get('version')} -> {d.get('upgrade_to_firmware') or '?'})"
              for d in devices if d.get("upgradable")]
    ctl("Firmware des equipements UniFi a jour", "Oui" if not a_jour else "Non", " ; ".join(a_jour))
    if "auto_upgrade" in mgmt:
        ctl("Mise a jour automatique du firmware", oui(mgmt.get("auto_upgrade")))
    eol = [noms.get(d.get("mac")) for d in devices if d.get("model_in_eol")]
    ctl("Aucun equipement en fin de vie", "Oui" if not eol else "Non", ", ".join(eol))
    hors = [noms.get(d.get("mac")) for d in devices if not ETATS.get(d.get("state"), "").startswith("OK")]
    ctl("Tous les equipements connectes au controleur", "Oui" if not hors else "Non", ", ".join(hors))
    ctl("SSH des equipements desactive ou par cle uniquement", "Non" if ssh_mdp else "Oui",
        "SSH actif avec mot de passe (identifiants des appareils definis dans le controleur)" if ssh_mdp else
        ("SSH actif, authentification par cle" if ssh_actif else "SSH desactive"))
    lan = [r for r in reseaux.values()]
    ctl("Reseau segmente en VLAN (plus d'un reseau local)", "Oui" if len(lan) > 1 else "Non",
        ", ".join(libelle_vlan(r) for r in sorted(lan, key=lambda r: r["vlan"])))
    seuls_defaut = [l for l in L["ports"] if l["Equipement"] in {noms.get(d.get("mac")) for d in devices}
                    and l["Etat"] == "Connecte" and "Tous les VLAN tagues" in l["Alerte"]]
    ctl("Ports d'acces sans profil All (tous les VLAN tagues)", "Oui" if not seuls_defaut else "Non",
        f"{len(seuls_defaut)} port(s) connecte(s) a un poste avec tous les VLAN tagues : un appareil branche "
        f"peut acceder a tous les reseaux" if seuls_defaut else "")
    inut = sum(1 for l in L["ports"] if "Actif mais non connecte" in l["Alerte"])
    ctl("Ports inutilises desactives", "Oui" if not inut else "Non", f"{inut} port(s) actif(s) sans cable" if inut else "")
    faibles = [f"{w['SSID']} ({w['Chiffrement']})" for w in L["wifi"] if "Chiffrement faible" in w["Alerte"]]
    if wlans:
        ctl("Wi-Fi chiffre en WPA2 / WPA3 (aucun reseau ouvert, WEP ou WPA)", "Oui" if not faibles else "Non",
            ", ".join(faibles))
        inv = [w for w in L["wifi"] if w["Reseau invite isole"]]
        ctl("Reseau Wi-Fi invite isole du reseau interne",
            "N/A" if not inv else ("Oui" if all(w["Reseau invite isole"] == "Oui" for w in inv) else "Non"),
            ", ".join(f"{w['SSID']} : {w['Reseau invite isole']}" for w in inv))
    passerelle = any(d.get("type") in ("ugw", "udm", "uxg") for d in devices)
    ctl("Detection / prevention d'intrusion (IDS / IPS) active",
        "N/A" if not passerelle else oui((ips.get("ips_mode") or "disabled") not in ("disabled", "")),
        "pas de passerelle UniFi sur ce site" if not passerelle else f"mode : {ips.get('ips_mode') or 'desactive'}")
    if snmp.get("enabled"):
        ctl("SNMP des equipements sans communaute par defaut",
            "Non" if snmp_comm.lower() in ("public", "private") else "Oui", "SNMP actif sur le site")
    if admins:
        lst = [f"{a.get('name') or a.get('email')} ({'super admin' if a.get('is_super') else a.get('role', '')})"
               for a in admins]
        ctl("Administrateurs du controleur nominatifs et en nombre limite", "A verifier",
            f"{len(admins)} administrateur(s) : " + ", ".join(lst))
    else:
        ctl("Administrateurs du controleur nominatifs et en nombre limite", "A verifier",
            "liste non lisible avec ce compte : verifier dans Parametres > Administrateurs")
    return len(devices), len(reseaux), len(wlans)


COLS = {
    "eq": ["Equipement", "IP", "Type", "Marque", "Modele", "Firmware", "S/N", "Nom SNMP", "Description",
           "Localisation", "Contact", "Uptime", "Dernier redemarrage", "Version SNMP", "Communaute par defaut",
           "Telnet", "HTTP", "HTTPS", "SSH", "Ports physiques", "Ports connectes", "Ports actifs non connectes",
           "VLANs", "Voisins LLDP", "Firmware a jour", "Fin de vie", "Source", "Statut", "Alerte"],
    "ports": ["Equipement", "Port", "Description", "Alias", "Type", "Admin", "Etat", "Vitesse (Mb/s)", "Mode",
              "VLAN natif", "VLANs non tagues", "VLANs tagues", "Reseaux tagues", "Profil", "PoE",
              "Securite du port", "Voisin LLDP", "Alerte"],
    "vlan": ["Controleur", "Site", "VLAN", "Nom", "Usage", "Sous-reseau", "DHCP", "Isolation", "Acces Internet",
             "IGMP snooping", "Ports connectes en natif", "Ports connectes tagues", "SSID", "Alerte"],
    "wifi": ["Equipement", "SSID", "Chiffrement", "Reseau invite isole", "VLAN", "Actif", "Commentaire", "Alerte"],
    "voisins": ["Equipement", "Port local", "Voisin", "Port voisin", "Description port voisin", "Chassis voisin"],
    "ctl": ["Equipement", "IP", "Type", "Point de controle", "Resultat", "Commentaire"],
}
SUFFIXES = {"eq": "", "ports": "_Ports", "vlan": "_VLAN", "wifi": "_Wifi", "voisins": "_Voisins", "ctl": "_Controles"}


def main():
    ap = argparse.ArgumentParser(description="Audit d'un controleur UniFi Network (lecture seule)")
    ap.add_argument("--nom", required=True, help="nom du controleur dans le rapport")
    ap.add_argument("--hote", required=True, help="IP ou nom du controleur")
    ap.add_argument("--port", type=int, default=0, help="port HTTPS (defaut : essai 443, 11443 puis 8443)")
    ap.add_argument("--site", default="", help="site(s) a auditer, separes par des virgules (defaut : tous)")
    ap.add_argument("--sortie", required=True)
    ap.add_argument("--verifier-tls", action="store_true")
    a = ap.parse_args()
    user, mdp = os.environ.get("UNIFI_USER", ""), os.environ.get("UNIFI_PASSWORD", "")
    os.makedirs(a.sortie, exist_ok=True)
    base = os.path.join(a.sortie, f"{a.nom}_Audit_Reseau")
    L = {k: [] for k in COLS}

    def echec(msg):
        ecrire(base + ".csv", COLS["eq"], [{"Equipement": a.nom, "IP": a.hote, "Type": "Controleur UniFi",
                                            "Marque": "Ubiquiti", "Source": "Controleur UniFi",
                                            "Statut": "INJOIGNABLE (controleur UniFi)", "Alerte": msg[:400]}])
        print(f"{a.nom} : ERREUR {msg}", file=sys.stderr)
        return 1

    if not user or not mdp:
        return echec("compte ou mot de passe du controleur non renseigne (ansible_user / mdp)")
    c = Controleur(a.hote, a.port, a.verifier_tls)
    try:
        c.connecter(user, mdp)
        sites = c.api("/api/self/sites")
        voulus = [s.strip().lower() for s in a.site.split(",") if s.strip()]
        if voulus:
            sites = [s for s in sites if s.get("name", "").lower() in voulus or (s.get("desc") or "").lower() in voulus]
        if not sites:
            return echec("aucun site accessible avec ce compte" + (f" (filtre : {a.site})" if voulus else ""))
        info = c.api("/api/s/%s/stat/sysinfo" % sites[0]["name"], optionnel=True)
        version = (info[0] if info else {}).get("version", "?")
        print(f"{a.nom} : {c.genre} {c.base}, UniFi Network {version}, {len(sites)} site(s)")
        for s in sites:
            nd, nr, nw = auditer_site(c, s, a.nom, L)
            print(f"  site {s.get('desc') or s['name']} : {nd} equipement(s), {nr} reseau(x), {nw} SSID")
        if info and info[0].get("update_available"):
            L["ctl"].append({"Equipement": a.nom, "IP": a.hote, "Type": "Controleur UniFi",
                             "Point de controle": "Application UniFi Network a jour", "Resultat": "Non",
                             "Commentaire": f"version {version}, mise a jour disponible"})
        elif info:
            L["ctl"].append({"Equipement": a.nom, "IP": a.hote, "Type": "Controleur UniFi",
                             "Point de controle": "Application UniFi Network a jour", "Resultat": "Oui",
                             "Commentaire": f"version {version}"})
    except ErreurApi as e:
        return echec(str(e))
    except Exception as e:  # reseau, JSON inattendu
        return echec(f"{type(e).__name__} : {e}")
    finally:
        c.deconnecter()
    for k, suf in SUFFIXES.items():
        ecrire(base + suf + ".csv", COLS[k], L[k])
    al = sum(1 for k in ("eq", "ports", "wifi") for l in L[k] if l.get("Alerte"))
    print(f"{a.nom} : {len(L['eq'])} equipement(s), {len(L['ports'])} port(s), {len(L['vlan'])} VLAN, "
          f"{len(L['wifi'])} SSID, {al} ligne(s) en alerte")
    return 0


if __name__ == "__main__":
    sys.exit(main())
