#!/usr/bin/env python3
# Audit_Reseau_SNMP.py
# Version      : 1.1
# Derniere modif : Configuration VLAN des ports (Q-BRIDGE-MIB) : mode Access / Trunk / Hybride, VLAN natif (PVID),
#                  VLANs non tagues et tagues, voisin LLDP du port
# v1.0         : Creation - audit des equipements reseau (switchs, bornes Wi-Fi) en SNMP, toutes marques
# Role         : Interroge UN equipement en SNMP (lecture seule) depuis la machine Ansible et ecrit 5 CSV
#                dans le dossier --sortie (Temp_CSV/RESEAU) :
#                  <eq>_Audit_Reseau.csv           1 ligne : modele, firmware, S/N, uptime, ports, LLDP, alertes
#                  <eq>_Audit_Reseau_Ports.csv     1 ligne par port physique (etat, vitesse, mode, VLAN natif,
#                                                  VLANs tagues / non tagues, voisin LLDP)
#                  <eq>_Audit_Reseau_Voisins.csv   voisins LLDP (topologie)
#                  <eq>_Audit_Reseau_Wifi.csv      SSID diffuses (bornes UniFi, MIB 802.11)
#                  <eq>_Audit_Reseau_Controles.csv points a verifier a la main (non visibles en SNMP)
# Usage        : lance par ansible/audit.yml (groupe [reseau] du .ini), ou a la main :
#                SNMP_COMMUNAUTE=xxx python3 Audit_Reseau_SNMP.py --hote SW01 --ip 192.168.1.2 --sortie /tmp/out
# Identifiants : variables d'environnement (jamais en argument) :
#                SNMP_VERSION (2c par defaut, 1 ou 3), SNMP_COMMUNAUTE, SNMP_PORT (161)
#                SNMPv3 : SNMP_V3_USER, SNMP_V3_NIVEAU (authPriv | authNoPriv | noAuthNoPriv),
#                         SNMP_V3_AUTH_PROTO (SHA), SNMP_V3_AUTH_PASS, SNMP_V3_PRIV_PROTO (AES), SNMP_V3_PRIV_PASS
# Prerequis    : outils net-snmp sur la machine Ansible : sudo apt install snmp
# En plus du SNMP : test de connexion TCP (sans authentification) sur 22 / 23 / 80 / 443 pour reperer
#                Telnet et l'administration HTTP non chiffree (--sans-test-ports pour le desactiver).
# ============================================================
import argparse
import csv
import os
import re
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timedelta

# OID UniFi (UBNT-UniFi-MIB, bornes UAP / U6 / U7) : nom des reseaux Wi-Fi diffuses.
# A verifier sur une borne si la feuille Wi-Fi reste vide : snmpbulkwalk -v2c -c COMM IP 1.3.6.1.4.1.41112.1.6.1.2.1
OID_UNIFI_ESSID = "1.3.6.1.4.1.41112.1.6.1.2.1.6"
OID_DOT11_SSID = "1.2.840.10036.1.1.1.9"          # IEEE802dot11-MIB dot11DesiredSSID (autres marques)
JOURS_SANS_REDEMARRAGE = 365

MARQUES = {"4526": "Netgear", "41112": "Ubiquiti", "4413": "Ubiquiti (EdgeSwitch)", "9": "Cisco",
           "29671": "Cisco Meraki", "11863": "TP-Link", "25506": "HPE / H3C", "11": "HP", "14823": "Aruba",
           "47196": "Aruba", "6486": "Alcatel-Lucent", "2011": "Huawei", "12356": "Fortinet", "14988": "MikroTik",
           "171": "D-Link", "674": "Dell", "8072": "Net-SNMP (Linux embarque)"}
TYPES_PORT = {"6", "62", "117", "71"}   # ethernetCsmacd, fastEther, gigabitEthernet, ieee80211 (radio)

ENV = os.environ


# ─── SNMP (outils net-snmp) ─────────────────────────────────
def base_args():
    v = ENV.get("SNMP_VERSION", "2c").lower().lstrip("v")
    a = ["-t", "3", "-r", "1", "-On", "-Oq", "-Ot", "-Oe", "-Le"]
    if v == "3":
        a += ["-v3", "-u", ENV.get("SNMP_V3_USER", ""), "-l", ENV.get("SNMP_V3_NIVEAU", "authPriv")]
        if ENV.get("SNMP_V3_AUTH_PASS"):
            a += ["-a", ENV.get("SNMP_V3_AUTH_PROTO", "SHA"), "-A", ENV["SNMP_V3_AUTH_PASS"]]
        if ENV.get("SNMP_V3_PRIV_PASS"):
            a += ["-x", ENV.get("SNMP_V3_PRIV_PROTO", "AES"), "-X", ENV["SNMP_V3_PRIV_PASS"]]
    else:
        a += ["-v1" if v == "1" else "-v2c", "-c", ENV.get("SNMP_COMMUNAUTE", "")]
    return a


def cible(ip):
    port = ENV.get("SNMP_PORT", "161")
    return f"udp:{ip}:{port}" if port != "161" else ip


def nettoie(val):
    val = val.strip()
    if len(val) >= 2 and val[0] == val[-1] == '"':
        val = val[1:-1]
    if re.match(r"^(No Such|No more variables|End of MIB)", val):
        return None
    return val.strip()


def parse(sortie):
    res = []
    for ligne in sortie.splitlines():
        if not ligne.startswith("."):
            if res and ligne.strip():          # valeur sur plusieurs lignes
                res[-1] = (res[-1][0], res[-1][1] + " " + ligne.strip())
            continue
        oid, _, val = ligne.partition(" ")
        res.append((oid.lstrip("."), nettoie(val)))
    return [(o, v) for o, v in res if v is not None]


def snmp_get(ip, oids, args=None):
    p = subprocess.run(["snmpget"] + (args or base_args()) + [cible(ip)] + oids,
                       capture_output=True, text=True, errors="replace", timeout=60)
    return dict(parse(p.stdout)), p


def snmp_walk(ip, oid, hexa=False):
    v1 = ENV.get("SNMP_VERSION", "2c").lstrip("v") == "1"
    cmd = (["snmpwalk" if v1 else "snmpbulkwalk"] + base_args() + (["-Ox"] if hexa else [])
           + ([] if v1 else ["-Cr25"]) + [cible(ip), oid])
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=180)
    except subprocess.TimeoutExpired:
        return {}
    return {o[len(oid) + 1:]: v for o, v in parse(p.stdout) if o.startswith(oid + ".")}


def communaute_par_defaut(ip):
    """La communaute public / private est-elle acceptee (en plus de celle fournie) ?"""
    ok = []
    for c in ("public", "private"):
        args = ["-t", "2", "-r", "0", "-On", "-Oq", "-Le", "-v2c", "-c", c]
        try:
            r, _ = snmp_get(ip, ["1.3.6.1.2.1.1.5.0"], args)
        except subprocess.TimeoutExpired:
            r = {}
        if r:
            ok.append(c)
    return ok


def port_ouvert(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=2):
            return True
    except OSError:
        return False


# ─── COLLECTE ───────────────────────────────────────────────
def duree(ticks):
    try:
        s = int(ticks) // 100
    except (TypeError, ValueError):
        return "", None
    j, r = divmod(s, 86400)
    return f"{j} j {r // 3600} h", j


def bits_ports(hexval):
    """PortList Q-BRIDGE (octets hexa, bit de poids fort du 1er octet = port de pont 1) -> {numeros}."""
    res = set()
    for i, octet in enumerate((hexval or "").split()):
        try:
            b = int(octet, 16)
        except ValueError:
            continue
        for j in range(8):
            if b & (0x80 >> j):
                res.add(str(i * 8 + j + 1))
    return res


def plages(vlans):
    """[1, 10, 11, 12, 20] -> '1, 10-12, 20'"""
    n = sorted({int(x) for x in vlans if str(x).isdigit()})
    out, i = [], 0
    while i < len(n):
        j = i
        while j + 1 < len(n) and n[j + 1] == n[j] + 1:
            j += 1
        out.append(str(n[i]) if i == j else f"{n[i]}-{n[j]}")
        i = j + 1
    return ", ".join(out)


def hexmac(v):
    return v.replace(" ", ":").lower() if re.fullmatch(r"([0-9A-Fa-f]{2} ){5}[0-9A-Fa-f]{2}", v or "") else v


def collecter(a):
    ip = a.ip
    sysd, p = snmp_get(ip, ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.3.0",
                            "1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.6.0"])
    if not sysd:
        err = (p.stderr or "").strip().splitlines()
        return None, (err[-1] if err else "pas de reponse")
    g = lambda n: sysd.get(f"1.3.6.1.2.1.1.{n}.0", "") or ""
    descr, objid = g(1), g(2).lstrip(".")
    ent = objid.split(".")[6] if objid.startswith("1.3.6.1.4.1.") and len(objid.split(".")) > 6 else ""
    d = {"descr": descr, "nom": g(5), "contact": g(4), "localisation": g(6), "marque": a.marque or MARQUES.get(ent, "")}
    d["uptime"], d["jours"] = duree(g(3))

    # ENTITY-MIB : chassis (classe 3) -> modele, S/N, firmware
    e = snmp_walk(ip, "1.3.6.1.2.1.47.1.1.1.1")
    col = lambda c: {k.split(".", 1)[1]: v for k, v in e.items() if k.startswith(f"{c}.")}
    classes, series, modeles, logiciels, firmwares, fabricants = col(5), col(11), col(13), col(10), col(9), col(12)
    chassis = [i for i, c in classes.items() if c == "3"] or sorted(series, key=lambda x: int(x) if x.isdigit() else 0)[:1]
    pick = lambda t: " - ".join(dict.fromkeys(t[i] for i in chassis if t.get(i)))
    d["sn"], d["modele"] = pick(series), pick(modeles)
    d["firmware"] = pick(logiciels) or pick(firmwares)
    if not d["marque"] and pick(fabricants):
        d["marque"] = pick(fabricants)

    # Bornes UniFi (MIB Ubiquiti) : modele / version si l'ENTITY-MIB est vide
    if not d["modele"] or not d["firmware"]:
        u, _ = snmp_get(ip, ["1.3.6.1.4.1.41112.1.6.3.3.0", "1.3.6.1.4.1.41112.1.6.3.6.0"])
        d["modele"] = d["modele"] or u.get("1.3.6.1.4.1.41112.1.6.3.3.0", "")
        d["firmware"] = d["firmware"] or u.get("1.3.6.1.4.1.41112.1.6.3.6.0", "")
        if (u.get("1.3.6.1.4.1.41112.1.6.3.3.0") or u.get("1.3.6.1.4.1.41112.1.6.3.6.0")) \
                and not d["marque"].startswith("Ubiquiti"):
            d["marque"] = "Ubiquiti"
    # Ubiquiti sur agent Net-SNMP generique (switchs UniFi USW : "Linux UBNT 4.4.153 ... mips")
    linux_nu = re.match(r"Linux\s+\S+\s+([0-9][0-9.]+)", descr or "")
    if re.search(r"\bUBNT\b|UniFi|\bUSW|EdgeSwitch", f"{descr} {d['nom']}", re.I) \
            and (not d["marque"] or d["marque"].startswith("Net-SNMP")):
        d["marque"] = "Ubiquiti"
    if linux_nu and not d["modele"]:
        # la description ne donne que le noyau : ni modele ni firmware exploitables
        d["modele"] = "(non fourni en SNMP)"
        d["firmware"] = d["firmware"] or f"(noyau Linux {linux_nu.group(1)}, firmware non fourni)"
    # Dernier recours : description systeme (ex. "GS308T 8-Port Gigabit Smart Managed Pro Switch, 1.0.3.1")
    if not d["modele"] and descr:
        d["modele"] = descr.split(",")[0].split(" ")[0][:40]
    if not d["firmware"]:
        m = re.search(r"(?:firmware|version|ver\.?|v)\s*:?\s*([0-9]+(?:\.[0-9A-Za-z]+){1,4})", descr, re.I) \
            or re.search(r"\b([0-9]+\.[0-9]+(?:\.[0-9A-Za-z]+){1,3})\b", descr)
        d["firmware"] = m.group(1) if m else ""

    # Interfaces
    w = lambda o: snmp_walk(ip, o)
    itype, iadmin, ioper = w("1.3.6.1.2.1.2.2.1.3"), w("1.3.6.1.2.1.2.2.1.7"), w("1.3.6.1.2.1.2.2.1.8")
    iname, idescr, ialias, ispeed = w("1.3.6.1.2.1.31.1.1.1.1"), w("1.3.6.1.2.1.2.2.1.2"), \
        w("1.3.6.1.2.1.31.1.1.1.18"), w("1.3.6.1.2.1.31.1.1.1.15")
    # VLAN natif par port (Q-BRIDGE-MIB) : port de pont -> ifIndex
    pont_if = w("1.3.6.1.2.1.17.1.4.1.2")
    if not pont_if:
        # dot1dBasePortIfIndex absent (switchs UniFi notamment) : port de pont N = Nieme port Ethernet
        eth_idx = sorted((i for i, t in itype.items() if t in TYPES_PORT and t != "71"),
                         key=lambda x: int(x) if x.isdigit() else 0)
        pont_if = {str(n): i for n, i in enumerate(eth_idx, 1)}
    pvid = {pont_if[bp]: v for bp, v in w("1.3.6.1.2.1.17.7.1.4.5.1.1").items() if bp in pont_if}
    vlans = w("1.3.6.1.2.1.17.7.1.4.3.1.1")
    # Appartenance aux VLAN : configuration statique (dot1qVlanStatic, index = VLAN), sinon etat courant
    # (dot1qVlanCurrent, index = TimeMark.VLAN). Membres (egress) - non tagues = tagues.
    membres = snmp_walk(ip, "1.3.6.1.2.1.17.7.1.4.3.1.2", hexa=True)
    non_tag = snmp_walk(ip, "1.3.6.1.2.1.17.7.1.4.3.1.4", hexa=True)
    if not membres:
        membres = snmp_walk(ip, "1.3.6.1.2.1.17.7.1.4.2.1.4", hexa=True)
        non_tag = snmp_walk(ip, "1.3.6.1.2.1.17.7.1.4.2.1.5", hexa=True)
    vl = lambda k: k.split(".")[-1]
    if_pont = {v: k for k, v in pont_if.items()}
    tag_par_port, untag_par_port = {}, {}
    for k, hx in membres.items():
        nt = bits_ports(non_tag.get(k, ""))
        for bp in bits_ports(hx):
            (untag_par_port if bp in nt else tag_par_port).setdefault(bp, set()).add(vl(k))
    if not vlans and membres:
        vlans = {vl(k): "" for k in membres}

    # LLDP (avant les ports : voisin affiche sur chaque port)
    lp_desc, lp_id = w("1.0.8802.1.1.2.1.3.7.1.4"), w("1.0.8802.1.1.2.1.3.7.1.3")
    rn, rp, rpd, rc = (w(f"1.0.8802.1.1.2.1.4.1.1.{c}") for c in (9, 7, 8, 5))
    nom_if = {}
    for idx in itype:
        for n in (iname.get(idx), idescr.get(idx)):
            if n:
                nom_if.setdefault(n.lower(), idx)
    voisins, voisin_if = [], {}
    for k, nom in rn.items():
        parts = k.split(".")
        loc = parts[1] if len(parts) >= 3 else ""
        idx = next((nom_if[c.lower()] for c in (lp_id.get(loc), lp_desc.get(loc)) if c and c.lower() in nom_if),
                   pont_if.get(loc) or (loc if loc in itype else None))
        port_voisin = hexmac(rp.get(k, ""))
        if idx:
            voisin_if.setdefault(idx, []).append(f"{nom} ({rpd.get(k) or port_voisin})" if nom else port_voisin)
        voisins.append({"Port local": lp_desc.get(loc) or lp_id.get(loc) or loc, "Voisin": nom,
                        "Port voisin": port_voisin, "Description port voisin": rpd.get(k, ""),
                        "Chassis voisin": hexmac(rc.get(k, ""))})
    d["voisins"] = " - ".join(sorted({v["Voisin"] for v in voisins if v["Voisin"]}))
    d["vlans"] = " - ".join(f"{k} {v}".strip() for k, v in sorted(vlans.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0))[:500]

    ports = []
    radios = 0
    for idx, t in sorted(itype.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0):
        if t not in TYPES_PORT:
            continue
        if t == "71":
            radios += 1
        adm, op = iadmin.get(idx, ""), ioper.get(idx, "")
        alerte = "Actif mais non connecte" if adm == "1" and op == "2" and t != "71" else ""
        bp = if_pont.get(idx)
        tg, ut = tag_par_port.get(bp, set()), untag_par_port.get(bp, set())
        mode = "" if not (tg or ut) else "Trunk" if tg else "Hybride" if len(ut) > 1 else "Access"
        ports.append({"Mode": mode, "VLANs non tagues": plages(ut), "VLANs tagues": plages(tg),
                      "Voisin LLDP": " - ".join(voisin_if.get(idx, [])), "Port": iname.get(idx) or idescr.get(idx, idx), "Description": idescr.get(idx, ""),
                      "Alias": ialias.get(idx, ""), "Admin": {"1": "Active", "2": "Desactive"}.get(adm, adm),
                      "Etat": {"1": "Connecte", "2": "Non connecte"}.get(op, op),
                      "Vitesse (Mb/s)": ispeed.get(idx, "") if op == "1" else "",
                      "VLAN natif": pvid.get(idx, ""), "Type": "Radio Wi-Fi" if t == "71" else "Ethernet",
                      "Alerte": alerte})
    eth = [x for x in ports if x["Type"] == "Ethernet"]
    d["nb_ports"], d["nb_connectes"] = len(eth), sum(1 for x in eth if x["Etat"] == "Connecte")
    d["nb_inutiles"] = sum(1 for x in eth if x["Alerte"])


    # Wi-Fi
    ssid = list(dict.fromkeys(v for v in list(w(OID_UNIFI_ESSID).values()) + list(w(OID_DOT11_SSID).values()) if v))
    wifi = [{"SSID": s} for s in ssid]

    # Type
    texte = f"{descr} {d['modele']}".lower()
    if a.type and a.type != "auto":
        d["type"] = {"switch": "Switch", "wifi": "Borne Wi-Fi", "borne": "Borne Wi-Fi"}.get(a.type.lower(), a.type)
    elif radios or ssid or re.search(r"\b(uap|u6|u7|uk-|access point|wax|wac|orbi)", texte):
        d["type"] = "Borne Wi-Fi"
    elif len(eth) >= 5 or re.search(r"switch|usw|gs\d|xs\d|m4\d", texte):
        d["type"] = "Switch"
    else:
        d["type"] = "Autre"
    return {"eq": d, "ports": ports, "voisins": voisins, "wifi": wifi}, ""


# ─── ECRITURE ───────────────────────────────────────────────
def ecrire(chemin, entetes, lignes):
    with open(chemin, "w", encoding="utf-8-sig", newline="") as f:
        wr = csv.DictWriter(f, fieldnames=entetes, delimiter=";", quoting=csv.QUOTE_ALL, extrasaction="ignore")
        wr.writeheader()
        for l in lignes:
            wr.writerow(l)


COL_EQ = ["Equipement", "IP", "Type", "Marque", "Modele", "Firmware", "S/N", "Nom SNMP", "Description",
          "Localisation", "Contact", "Uptime", "Dernier redemarrage", "Version SNMP", "Communaute par defaut",
          "Telnet", "HTTP", "HTTPS", "SSH", "Ports physiques", "Ports connectes", "Ports actifs non connectes",
          "VLANs", "Voisins LLDP", "Statut", "Alerte"]

CONTROLES = {
    "*": ["Mot de passe administrateur par defaut change",
          "Firmware a jour (comparer a la derniere version publiee par l'editeur)",
          "Administration limitee au reseau / VLAN d'administration"],
    "Switch": ["Ports inutilises desactives ou dans un VLAN poubelle", "VLAN 1 non utilise pour les donnees"],
    "Borne Wi-Fi": ["Chiffrement WPA2 ou WPA3 (aucun reseau ouvert ni WEP)", "Reseau invite isole du reseau interne",
                    "WPS desactive", "Cle Wi-Fi robuste et changee recemment"],
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hote", required=True)
    ap.add_argument("--ip", required=True)
    ap.add_argument("--type", default="auto")
    ap.add_argument("--marque", default="")
    ap.add_argument("--sortie", required=True)
    ap.add_argument("--sans-test-ports", action="store_true")
    a = ap.parse_args()
    if not shutil.which("snmpget"):
        print("ERREUR : outils SNMP absents sur la machine Ansible -> sudo apt install snmp", file=sys.stderr)
        return 2
    os.makedirs(a.sortie, exist_ok=True)
    base = os.path.join(a.sortie, f"{a.hote}_Audit_Reseau")
    version = "v3" if ENV.get("SNMP_VERSION", "2c").lstrip("v") == "3" else "v" + ENV.get("SNMP_VERSION", "2c").lstrip("v")

    res, err = collecter(a)
    tcp = {} if a.sans_test_ports else {n: ("Oui" if port_ouvert(a.ip, p) else "Non")
                                        for n, p in (("Telnet", 23), ("HTTP", 80), ("HTTPS", 443), ("SSH", 22))}
    if res is None:
        ligne = {"Equipement": a.hote, "IP": a.ip, "Type": a.type if a.type != "auto" else "", "Marque": a.marque,
                 "Version SNMP": version, "Statut": "INJOIGNABLE (SNMP)", "Alerte": f"Pas de reponse SNMP : {err}", **tcp}
        ecrire(base + ".csv", COL_EQ, [ligne])
        print(f"{a.hote} : INJOIGNABLE en SNMP ({err})")
        return 0

    d = res["eq"]
    defaut = communaute_par_defaut(a.ip)
    if version != "v3" and ENV.get("SNMP_COMMUNAUTE", "").lower() in ("public", "private"):
        defaut = sorted(set(defaut) | {ENV["SNMP_COMMUNAUTE"].lower()})
    alertes = []
    if defaut:
        alertes.append(f"Communaute SNMP par defaut acceptee ({', '.join(defaut)})")
    if tcp.get("Telnet") == "Oui":
        alertes.append("Telnet ouvert")
    if tcp.get("HTTP") == "Oui" and tcp.get("HTTPS") != "Oui":
        alertes.append("Administration HTTP sans chiffrement")
    elif tcp.get("HTTP") == "Oui":
        alertes.append("HTTP ouvert (verifier la redirection vers HTTPS)")
    if d["jours"] is not None and d["jours"] > JOURS_SANS_REDEMARRAGE:
        alertes.append(f"Non redemarre depuis {d['jours']} j (firmware probablement pas mis a jour)")
    redem = (datetime.now() - timedelta(days=d["jours"])).strftime("%d/%m/%Y") if d["jours"] is not None else ""

    ligne = {"Equipement": a.hote, "IP": a.ip, "Type": d["type"], "Marque": d["marque"], "Modele": d["modele"],
             "Firmware": d["firmware"], "S/N": d["sn"] or "(non fourni en SNMP)", "Nom SNMP": d["nom"],
             "Description": d["descr"][:250], "Localisation": d["localisation"], "Contact": d["contact"],
             "Uptime": d["uptime"], "Dernier redemarrage": redem, "Version SNMP": version,
             "Communaute par defaut": ", ".join(defaut) or "Non", **tcp,
             "Ports physiques": d["nb_ports"], "Ports connectes": d["nb_connectes"],
             "Ports actifs non connectes": d["nb_inutiles"], "VLANs": d["vlans"], "Voisins LLDP": d["voisins"],
             "Statut": "OK", "Alerte": " | ".join(alertes)}
    ecrire(base + ".csv", COL_EQ, [ligne])
    ecrire(base + "_Ports.csv", ["Equipement", "Port", "Description", "Alias", "Type", "Admin", "Etat",
                                 "Vitesse (Mb/s)", "Mode", "VLAN natif", "VLANs non tagues", "VLANs tagues",
                                 "Voisin LLDP", "Alerte"],
           [{"Equipement": a.hote, **p} for p in res["ports"]])
    ecrire(base + "_Voisins.csv", ["Equipement", "Port local", "Voisin", "Port voisin", "Description port voisin",
                                   "Chassis voisin"], [{"Equipement": a.hote, **v} for v in res["voisins"]])
    ecrire(base + "_Wifi.csv", ["Equipement", "SSID", "Chiffrement", "Reseau invite isole", "Commentaire"],
           [{"Equipement": a.hote, **s, "Chiffrement": "A verifier", "Reseau invite isole": "A verifier"}
            for s in res["wifi"]])
    ctrl = CONTROLES["*"] + CONTROLES.get(d["type"], [])
    ecrire(base + "_Controles.csv", ["Equipement", "IP", "Type", "Point de controle", "Resultat", "Commentaire"],
           [{"Equipement": a.hote, "IP": a.ip, "Type": d["type"], "Point de controle": c, "Resultat": "A verifier"}
            for c in ctrl])
    print(f"{a.hote} : {d['type']} {d['marque']} {d['modele']} {d['firmware']} S/N {d['sn'] or '-'} | "
          f"{d['nb_ports']} ports, {len(res['voisins'])} voisin(s) LLDP, {len(res['wifi'])} SSID | "
          f"alertes : {ligne['Alerte'] or 'aucune'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
