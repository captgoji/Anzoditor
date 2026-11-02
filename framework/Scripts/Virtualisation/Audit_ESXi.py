#!/usr/bin/env python3
# Audit_ESXi.py
# Version      : 1.0
# Derniere modif : Creation - audit VMware (hote ESXi isole ou vCenter) en LECTURE SEULE via l'API vSphere
# Role         : Depuis la machine Ansible, interroge un ESXi ou un vCenter (tous ses hotes) et ecrit :
#                  <sortie>/HV/<hote>_Audit_Hyperviseurs.csv   meme format que 20_Audit_Hyperviseurs (Hyper-V)
#                  <sortie>/<cible>_Audit_Virtu_VMs.csv         VM : etat, OS, ressources, VMware Tools, snapshots
#                  <sortie>/<cible>_Audit_Virtu_Stockage.csv    datastores et remplissage
#                  <sortie>/<cible>_Audit_Virtu_Securite.csv    version / fin de support, SSH, ESXi Shell,
#                                                               mode verrouillage, NTP, syslog, comptes locaux
# Usage        : lance par ansible/audit.yml (section [esxi] du .ini), ou a la main :
#                VSPHERE_USER=audit@vsphere.local VSPHERE_PASSWORD=... python3 Audit_ESXi.py --cible ESX01 \
#                    --hote 192.168.1.20 --sortie Temp_CSV/VIRTU
#                Un compte en lecture seule suffit (role "Lecture seule" / "Read-only").
#                Si un vCenter existe : declarer le vCenter seul (ses hotes sont tous audites).
# Prerequis    : pyVmomi sur la machine Ansible : sudo apt install python3-pyvmomi
#                (ou pip install --break-system-packages pyvmomi)
# ============================================================
import argparse
import csv
import os
import ssl
import sys
from datetime import date, datetime, timezone

try:
    from pyVim.connect import Disconnect, SmartConnect
    from pyVmomi import vim
except ImportError:
    sys.exit("ERREUR : pyVmomi absent sur la machine Ansible -> sudo apt install python3-pyvmomi")

# Fin de support general VMware (End of General Support) - a mettre a jour
FIN_SUPPORT = {"5.5": date(2018, 9, 19), "6.0": date(2020, 3, 12), "6.5": date(2022, 10, 15),
               "6.7": date(2022, 10, 15), "7.0": date(2025, 10, 2), "8.0": date(2027, 10, 11)}
SNAPSHOT_JOURS = 7
STOCKAGE_PCT = 85
AUJ = datetime.now(timezone.utc)

COL_HV = ["Nom", "IP (Physique)", "IP (vEthernet)", "Adresse MAC", "Roles", "Type d'hyperviseur", "OS",
          "Integre au domaine", "Nom de Domaine", "Cluster/Standalone", "Nom du cluster", "Processeurs", "RAM",
          "Stockage", "Nb VM hebergees", "Nb VM demarrees", "VMs hebergees", "Fabricant", "Modele", "S/N"]
COL_VM = ["Hyperviseur", "Hote", "VM", "ID", "Type", "Etat", "OS", "vCPU", "RAM (Go)", "Disque (Go)",
          "Demarrage auto", "Agent invite", "Version materielle", "Snapshots", "Plus ancien snapshot (j)",
          "Derniere sauvegarde", "Sauvegarde planifiee", "IP", "Alerte"]
COL_ST = ["Hyperviseur", "Hote", "Stockage", "Type", "Partage", "Taille (Go)", "Utilise (Go)", "Utilise (%)", "Alerte"]
COL_SEC = ["Hyperviseur", "Controle", "Valeur", "Statut", "Commentaire"]


def ecrire(chemin, colonnes, lignes):
    os.makedirs(os.path.dirname(chemin), exist_ok=True)
    with open(chemin, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=colonnes, delimiter=";", quoting=csv.QUOTE_ALL, extrasaction="ignore")
        w.writeheader()
        w.writerows(lignes)


def go(octets):
    return round((octets or 0) / 1024 ** 3, 1)


def statut_version(version):
    branche = ".".join((version or "").split(".")[:2])
    fin = FIN_SUPPORT.get(branche)
    if not fin:
        return "Info", "Branche non référencée : vérifier le support éditeur"
    jours = (fin - date.today()).days
    if jours < 0:
        return "Critique", f"Fin de support le {fin:%d/%m/%Y} : plus de correctifs de sécurité"
    if jours < 180:
        return "Attention", f"Fin de support le {fin:%d/%m/%Y} (dans {jours} j)"
    return "OK", f"Supporté jusqu'au {fin:%d/%m/%Y}"


def vue(content, type_):
    v = content.viewManager.CreateContainerView(content.rootFolder, [type_], True)
    try:
        return list(v.view)
    finally:
        v.Destroy()


def proprietes(content, type_, chemins):
    """Lecture groupee (PropertyCollector) : {objet: {chemin: valeur}} - rapide sur les gros inventaires et
    insensible aux proprietes illisibles d'un objet."""
    v = content.viewManager.CreateContainerView(content.rootFolder, [type_], True)
    try:
        spec = vim.PropertyCollector.FilterSpec(
            objectSet=[vim.PropertyCollector.ObjectSpec(obj=v, skip=True, selectSet=[
                vim.PropertyCollector.TraversalSpec(name="t", path="view", skip=False, type=vim.view.ContainerView)])],
            propSet=[vim.PropertyCollector.PropertySpec(type=type_, pathSet=chemins)])
        res, opts = {}, vim.PropertyCollector.RetrieveOptions(maxObjects=500)
        r = content.propertyCollector.RetrievePropertiesEx([spec], opts)
        while r:
            for o in r.objects:
                res[o.obj] = {p.name: p.val for p in (o.propSet or [])}
            r = content.propertyCollector.ContinueRetrievePropertiesEx(r.token) if r.token else None
        return res
    finally:
        v.Destroy()


def snapshots(liste):
    for s in liste or []:
        yield s
        yield from snapshots(s.childSnapshotList)


def sur(f, defaut=""):
    try:
        r = f()
        return defaut if r is None else r
    except Exception:
        return defaut


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cible", required=True, help="nom de l'equipement dans l'inventaire")
    ap.add_argument("--hote", required=True, help="adresse de l'ESXi ou du vCenter")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--sortie", required=True)
    a = ap.parse_args()

    ctx = ssl._create_unverified_context()   # certificats auto-signes habituels sur ESXi
    try:
        si = SmartConnect(host=a.hote, port=a.port, user=os.environ.get("VSPHERE_USER", ""),
                          pwd=os.environ.get("VSPHERE_PASSWORD", ""), sslContext=ctx)
    except Exception as e:
        msg = getattr(e, "msg", None) or str(e)
        ecrire(os.path.join(a.sortie, f"{a.cible}_Audit_Virtu_Securite.csv"), COL_SEC,
               [{"Hyperviseur": a.cible, "Controle": "Connexion", "Valeur": "Echec", "Statut": "Critique",
                 "Commentaire": msg[:300]}])
        print(f"{a.cible} : INJOIGNABLE ({msg[:200]})")
        return 0
    try:
        auditer(si, a)
    finally:
        Disconnect(si)
    return 0


def auditer(si, a):
    content = si.RetrieveContent()
    about = content.about
    est_vc = about.apiType == "VirtualCenter"
    sec, vms_l, st_l = [], [], []

    def ajout(hv, ctrl, val, statut, com=""):
        sec.append({"Hyperviseur": hv, "Controle": ctrl, "Valeur": val, "Statut": statut, "Commentaire": com})

    if est_vc:
        st, com = statut_version(about.version)
        ajout(a.cible, "Version", f"{about.fullName}", st, "vCenter : " + com)

    hotes = vue(content, vim.HostSystem)
    pvm = proprietes(content, vim.VirtualMachine, [
        "name", "runtime.powerState", "runtime.host", "config.template", "config.hardware.numCPU",
        "config.hardware.memoryMB", "config.guestFullName", "config.version", "guest.guestFullName",
        "guest.toolsVersionStatus2", "guest.ipAddress", "summary.storage.committed", "snapshot"])
    for h in hotes:
        nom = h.name
        prod = sur(lambda: h.summary.config.product)
        version = sur(lambda: prod.version, "")
        hw = sur(lambda: h.hardware.systemInfo)
        sn = sur(lambda: hw.serialNumber, "")
        if not sn:
            for i in sur(lambda: hw.otherIdentifyingInfo, []) or []:
                if sur(lambda: i.identifierType.key) in ("ServiceTag", "SerialNumberTag", "EnclosureSerialNumberTag"):
                    sn = i.identifierValue
                    break
        cpu = sur(lambda: h.hardware.cpuPkg[0].description, "")
        nb = sur(lambda: h.hardware.cpuInfo.numCpuPackages, "")
        coeurs = sur(lambda: h.hardware.cpuInfo.numCpuCores, "")
        parent = sur(lambda: h.parent)
        cluster = parent.name if isinstance(parent, vim.ClusterComputeResource) else ""
        ips = []
        for vn in sur(lambda: h.config.network.vnic, []) or []:
            ip = sur(lambda: vn.spec.ip.ipAddress, "")
            if ip:
                ips.append(f"{vn.device} {ip}")
        macs = sorted({p.mac for p in sur(lambda: h.config.network.pnic, []) or [] if sur(lambda: p.mac)})
        datastores = sur(lambda: h.datastore, []) or []
        vms = [v for v, p in pvm.items() if p.get("runtime.host") == h and not p.get("config.template")]
        allumees = [v for v in vms if pvm[v].get("runtime.powerState") == "poweredOn"]

        ecrire(os.path.join(a.sortie, "HV", f"{nom}_Audit_Hyperviseurs.csv"), COL_HV, [{
            "Nom": nom, "IP (Physique)": " - ".join(ips), "Adresse MAC": " - ".join(macs),
            "Roles": ("Géré par vCenter " + a.cible) if est_vc else "Hôte isolé",
            "Type d'hyperviseur": "VMware ESXi", "OS": sur(lambda: prod.fullName, ""),
            "Integre au domaine": "", "Cluster/Standalone": "Cluster" if cluster else "Standalone",
            "Nom du cluster": cluster,
            "Processeurs": f"{nb} x {cpu} ({coeurs} cœurs)" if cpu else "",
            "RAM": f"{go(sur(lambda: h.hardware.memorySize, 0)):.0f} Go",
            "Stockage": " | ".join(f"{d.name} {go(d.summary.capacity)} Go (libre : {go(d.summary.freeSpace)} Go)"
                                   for d in datastores),
            "Nb VM hebergees": len(vms), "Nb VM demarrees": len(allumees),
            "VMs hebergees": " - ".join(sorted(f"{pvm[v].get('name')} ({'Running' if v in allumees else 'Off'})"
                                               for v in vms)),
            "Fabricant": sur(lambda: hw.vendor, ""), "Modele": sur(lambda: hw.model, ""), "S/N": sn}])

        # Securite de l'hote
        st, com = statut_version(version)
        ajout(nom, "Version", f"{sur(lambda: prod.fullName, '')}", st, com)
        services = {s.key: s for s in sur(lambda: h.configManager.serviceSystem.serviceInfo.service, []) or []}
        for cle, libelle in (("TSM-SSH", "Acces SSH"), ("TSM", "ESXi Shell")):
            s = services.get(cle)
            if s is None:
                ajout(nom, libelle, "Inconnu", "N/A")
                continue
            ajout(nom, libelle, ("Démarré" if s.running else "Arrêté") + f" (démarrage : {s.policy})",
                  "Attention" if s.running or s.policy == "on" else "OK",
                  "À n'activer que le temps d'une intervention" if s.running or s.policy == "on" else "")
        lock = sur(lambda: h.config.lockdownMode, "") or sur(lambda: h.configManager.hostAccessManager.lockdownMode, "")
        if est_vc:
            ajout(nom, "Mode verrouillage", str(lock) or "Inconnu",
                  "OK" if lock in ("lockdownNormal", "lockdownStrict") else "Attention",
                  "" if lock in ("lockdownNormal", "lockdownStrict") else
                  "Hôte administrable en direct malgré vCenter : activer le mode verrouillage normal")
        ntp = sur(lambda: h.config.dateTimeInfo.ntpConfig.server, []) or []
        ntpd = services.get("ntpd")
        ajout(nom, "NTP", ", ".join(ntp) or "Aucun serveur", "OK" if ntp and ntpd and ntpd.running else "Attention",
              "" if ntp and ntpd and ntpd.running else "Heure non synchronisée : journaux inexploitables")
        logh = ""
        try:
            opt = h.configManager.advancedOption.QueryOptions("Syslog.global.logHost")
            logh = opt[0].value if opt else ""
        except Exception:
            pass
        ajout(nom, "Syslog distant", logh or "Non configuré", "OK" if logh else "Attention",
              "" if logh else "Journaux uniquement sur l'hôte : perdus en cas de compromission ou de panne")
        uptime = sur(lambda: h.summary.quickStats.uptime, 0) or 0
        ajout(nom, "Dernier redémarrage", f"il y a {uptime // 86400} j", "Attention" if uptime > 365 * 86400 else "Info",
              "Plus d'un an sans redémarrage : correctifs probablement pas appliqués" if uptime > 365 * 86400 else "")

        # Datastores
        for d in datastores:
            cap, libre = d.summary.capacity or 0, d.summary.freeSpace or 0
            p = round(100 * (cap - libre) / cap, 1) if cap else 0
            st_l.append({"Hyperviseur": a.cible, "Hote": nom, "Stockage": d.name, "Type": d.summary.type,
                         "Partage": "Oui" if sur(lambda: d.summary.multipleHostAccess, False) else "Non",
                         "Taille (Go)": go(cap), "Utilise (Go)": go(cap - libre), "Utilise (%)": p,
                         "Alerte": f"Rempli à plus de {STOCKAGE_PCT} %" if p > STOCKAGE_PCT else ""})

        # VM
        for v in vms:
            p = pvm[v]
            snaps = list(snapshots(sur(lambda: p.get("snapshot").rootSnapshotList, [])))
            age = max(((AUJ - s.createTime).days for s in snaps), default=None)
            tools = p.get("guest.toolsVersionStatus2") or ""
            outils = {"guestToolsCurrent": "À jour", "guestToolsNeedUpgrade": "À mettre à jour",
                      "guestToolsNotInstalled": "Absents", "guestToolsUnmanaged": "Open VM Tools",
                      "guestToolsSupportedNew": "À jour", "guestToolsSupportedOld": "À mettre à jour",
                      "guestToolsTooOld": "Trop anciens", "guestToolsBlacklisted": "Bloqués"}.get(tools, tools)
            alertes = []
            if age is not None and age > SNAPSHOT_JOURS:
                alertes.append(f"Snapshot de {age} j (dégrade les performances, n'est pas une sauvegarde)")
            if outils in ("Absents", "Trop anciens") and v in allumees:
                alertes.append("VMware Tools absents ou trop anciens")
            vms_l.append({
                "Hyperviseur": a.cible, "Hote": nom, "VM": p.get("name", ""), "ID": v._moId, "Type": "VM",
                "Etat": {"poweredOn": "Démarrée", "poweredOff": "Arrêtée", "suspended": "Suspendue"}.get(
                    p.get("runtime.powerState"), ""),
                "OS": p.get("guest.guestFullName") or p.get("config.guestFullName") or "",
                "vCPU": p.get("config.hardware.numCPU", ""),
                "RAM (Go)": round((p.get("config.hardware.memoryMB") or 0) / 1024, 1),
                "Disque (Go)": go(p.get("summary.storage.committed")),
                "Agent invite": outils, "Version materielle": p.get("config.version", ""),
                "Snapshots": len(snaps), "Plus ancien snapshot (j)": age if age is not None else "",
                "Derniere sauvegarde": "", "Sauvegarde planifiee": "Non relevé (outil tiers)",
                "IP": p.get("guest.ipAddress") or "", "Alerte": " | ".join(alertes)})

        # Comptes locaux (hote isole uniquement)
        if not est_vc:
            try:
                comptes = content.userDirectory.RetrieveUserGroups(None, "", None, None, True, True, False)
                noms = sorted(u.principal for u in comptes if not u.group)
                ajout(nom, "Comptes locaux", ", ".join(noms), "Info",
                      "Vérifier qu'aucun compte n'est partagé ; root ne devrait servir qu'en secours")
            except Exception as e:
                ajout(nom, "Comptes locaux", "Non lisible", "N/A", str(e)[:200])

    ecrire(os.path.join(a.sortie, f"{a.cible}_Audit_Virtu_VMs.csv"), COL_VM, vms_l)
    ecrire(os.path.join(a.sortie, f"{a.cible}_Audit_Virtu_Stockage.csv"), COL_ST, st_l)
    ecrire(os.path.join(a.sortie, f"{a.cible}_Audit_Virtu_Securite.csv"), COL_SEC, sec)
    print(f"{a.cible} : {'vCenter' if est_vc else 'ESXi'} {about.version} build {about.build} | {len(hotes)} hôte(s), "
          f"{len(vms_l)} VM, {len(st_l)} datastore(s) | points : "
          + (", ".join(f"{s['Hyperviseur']} {s['Controle']}" for s in sec if s["Statut"] in ("Critique", "Attention"))
             or "aucun"))


if __name__ == "__main__":
    sys.exit(main())
