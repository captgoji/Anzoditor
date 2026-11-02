# Anzoditor — audit de sécurité d'un SI lancé depuis WSL avec Ansible

Anzoditor audite en une commande tout le système d'information d'un client : Active Directory, serveurs Windows et Linux, hyperviseurs, partages, équipements réseau, Microsoft 365 et Google Workspace. Tout est lancé depuis un poste Windows (WSL) via Ansible, **sans rien installer sur les serveurs audités**. Les résultats sont rassemblés dans des classeurs Excel et une synthèse destinée au client (notes par domaine, priorités, plan d'action).

```
WSL (Ansible)  ──WinRM 5985──▶  serveurs Windows   (scripts PowerShell du framework, copiés puis supprimés)
               ──SSH 22──────▶  serveurs Linux     (scripts shell, lecture seule)
               ──API─────────▶  vCenter / ESXi, contrôleur UniFi, Microsoft Graph, Google Admin SDK
               ──SNMP 161────▶  switchs et bornes Wi-Fi
        ▼
rapports/<date>_<client>_audit/   CSV, journaux, Excel, Synthese_Audit.xlsx, statut.csv
```

---

## Sommaire

- [Ce qui est audité](#ce-qui-est-audité)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Structure du dépôt](#structure-du-dépôt)
- [Décrire un client : le fichier .ini](#décrire-un-client--le-fichier-ini)
- [Profils : quels scripts sur quels serveurs](#profils--quels-scripts-sur-quels-serveurs)
- [Lancer un audit](#lancer-un-audit)
- [Suivre un audit en cours](#suivre-un-audit-en-cours)
- [Résultats](#résultats)
- [Synthèse client](#synthèse-client)
- [Ports et comptes nécessaires](#ports-et-comptes-nécessaires)
- [Dépannage](#dépannage)
- [Ajouter un script](#ajouter-un-script)
- [Sécurité et confidentialité](#sécurité-et-confidentialité)

---

## Ce qui est audité

| Périmètre | Source | Contenu |
|---|---|---|
| Comptes AD | `10_`, `11_` | Comptes Tier 0 (adminCount=1) et standards : activité, mot de passe, groupes, services et tâches planifiées sous le compte |
| OU | `13_` | Arborescence des OU |
| Hyper-V | `20_` | Hôtes, rôles, ressources, VM hébergées, numéro de série |
| Serveurs / postes | `21_`, `22_` | OS, réseau, activation, FSMO, source de temps, matériel |
| Réplication AD | `30_` | `repadmin /showrepl` |
| Partages et NTFS | `31_` | ACL de chaque dossier, droits de partage, liens DFS suivis, schémas `.html` / `.txt` de l'arborescence |
| GPO | `32_`, `37_` | Inventaire des GPO **et** contrôle du contenu (SYSVOL) par rapport au référentiel de durcissement `Referentiel/gpo.md` (+ LAPS, Autorun, LSA, spouleur sur DC, clés BitLocker dans l'AD) |
| Groupes AD | `33_` | Membres effectifs, imbrication, chemins vers les groupes privilégiés, utilisation dans les ACL NTFS et les GPO |
| PSO / silos | `34_`, `35_` | Stratégies de mot de passe affinées, silos d'authentification |
| LAPS | `36_` | Mot de passe LAPS présent par ordinateur (AD et Entra ID) |
| Applications | `CheckApp.ps1` / `.sh` | Logiciels installés, ports en écoute, moteurs PHP / Node.js et applications web, versions vulnérables |
| Linux | `Audit_Linux.sh`, `Audit_Linux_Comptes.sh` | OS, matériel, interfaces, services, comptes locaux (état du mot de passe avec sudo) |
| Proxmox VE | `Audit_Proxmox.pl` | Nœuds, VM / conteneurs, stockage, sauvegardes, accès (lancé automatiquement sur un Linux Proxmox) |
| VMware | `Audit_ESXi.py` | vCenter ou ESXi isolés via l'API vSphere (lecture seule) |
| Switchs / bornes | `Audit_Reseau_SNMP.py` | Modèle, firmware, S/N, ports, VLAN par port (Q-BRIDGE), voisins LLDP, Telnet/HTTP, communauté par défaut |
| UniFi | `Audit_UniFi.py` | Contrôleur UniFi : VLAN créés, profils et configuration de chaque port, Wi-Fi (sécurité, VLAN, isolation invité), firmware, fin de vie |
| Microsoft 365 | `Audit_M365.py` | Comptes, MFA, rôles, invités, appareils, LAPS Entra, **accès conditionnel et Intune analysés par leur contenu** (MFA, BitLocker, LAPS, ASR, Autorun…) |
| Google Workspace | `Audit_GWS.py` | Comptes, validation en 2 étapes, super admins, groupes, paramètres de sécurité |

Tous les audits sont **en lecture seule**.

---

## Prérequis

### Poste qui lance l'audit (WSL Ubuntu)

```bash
sudo apt update
sudo apt install -y ansible python3-winrm python3-openpyxl sshpass
ansible-galaxy collection install ansible.windows
```

| Paquet | Utile pour |
|---|---|
| `ansible` (ansible-core 2.15+, testé en 2.19 / 2.21) | tout |
| `python3-winrm` | serveurs Windows (WinRM / NTLM) |
| `sshpass` | serveurs Linux avec mot de passe (inutile avec une clé SSH) |
| `python3-openpyxl` | génération des Excel et de la synthèse |
| `snmp` | *optionnel* — équipements réseau `[reseau]` |
| `python3-pyvmomi` | *optionnel* — VMware `[esxi]` |

Microsoft 365, Google Workspace et UniFi n'ont besoin que de Python 3 (bibliothèque standard).

### Serveurs audités

- **Windows** : WinRM actif (`winrm quickconfig`), port 5985 joignable, compte administrateur (de domaine sur les DC). PowerShell 5.1. Les modules RSAT AD / GPMC sont présents sur les DC.
- **Linux** : SSH, un compte avec shell ; sudo (ou connexion root) recommandé pour le numéro de série, l'état des mots de passe et Proxmox.

---

## Installation

```bash
cd ~
git clone https://github.com/<organisation>/Anzoditor.git
cd Anzoditor
chmod +x lancer_audit.sh suivi_audit.sh
cp clients/EXEMPLE.ini clients/MonClient.ini
chmod 600 clients/*.ini
```

> Travailler **dans le système de fichiers WSL** (`~/Anzoditor`), pas sous `/mnt/c` : Ansible y ignore `ansible.cfg` pour cause de droits trop ouverts, et les performances sont bien meilleures. Pour retrouver les rapports côté Windows : `\\wsl.localhost\Ubuntu\home\<utilisateur>\Anzoditor\rapports`, ou variable `COPIE_WINDOWS` en tête de `lancer_audit.sh`.

---

## Structure du dépôt

```
Anzoditor/
├─ lancer_audit.sh              ← point d'entrée : ./lancer_audit.sh CLIENT
├─ suivi_audit.sh               ← suivi en direct d'un audit en cours
├─ audit.yml                    ← playbook (Windows, Linux, VMware, SNMP, UniFi, synthèse)
├─ suivi.yml                    ← playbook de suivi (lecture seule)
├─ profils.yml                  ← profils de serveur -> scripts lancés
├─ ansible.cfg
├─ clients/
│   ├─ EXEMPLE.ini              ← modèle commenté
│   └─ <CLIENT>.ini             ← un fichier par client (NE PAS COMMITTER)
├─ framework/
│   ├─ Process_excels.py        ← CSV -> Excel (selon modules_config.json)
│   ├─ Synthese_audit.py        ← Synthese_Audit.xlsx (notes, priorités, plan d'action)
│   ├─ modules_config.json      ← CSV -> modèle / feuille / classeur Excel
│   └─ Scripts/
│       ├─ PowerShell/          ← 10_ à 37_ (audit Windows / AD)
│       ├─ Applications/        ← CheckApp.ps1, CheckApp.sh
│       ├─ Linux/               ← Audit_Linux.sh, Audit_Linux_Comptes.sh
│       ├─ Virtualisation/      ← Audit_ESXi.py, Audit_Proxmox.pl
│       ├─ Reseau/              ← Audit_Reseau_SNMP.py, Audit_UniFi.py
│       ├─ M365/                ← Audit_M365.py, Audit_M365_Securite.py
│       ├─ GoogleWorkspace/     ← Audit_GWS.py
│       └─ Python/              ← TemplateAudit*.py (modèles Excel)
├─ Referentiel/
│   └─ gpo.md                   ← référentiel de durcissement GPO
└─ rapports/                    ← un dossier par audit (NE PAS COMMITTER)
```

Les noms de fichiers et de dossiers sont sensibles à la casse sous Linux (`GoogleWorkspace`, `Audit_UniFi.py`, `Audit_Proxmox.pl`).

---

## Décrire un client : le fichier .ini

Un fichier `clients/<CLIENT>.ini` par client, au format inventaire Ansible. Le modèle `clients/EXEMPLE.ini` est commenté ligne par ligne.

```ini
[all:vars]
client=ACME
m365_tenant=acme.onmicrosoft.com      ; facultatif : audit Microsoft 365
; gws_domaine=acme.fr                  ; facultatif : audit Google Workspace
; gws_admin=admin@acme.fr

[windows]
DC01      ansible_host=10.0.0.10  ansible_user='ACME\admin-audit'  profil=dc_principal
DC02      ansible_host=10.0.0.11  ansible_user='ACME\admin-audit'  profil=dc
SRV-FIC   ansible_host=10.0.0.12  ansible_user='ACME\admin-audit'  profil=serveur,fichiers  audit_ntfs_depth=2
HV01      ansible_host=10.0.0.13  ansible_user=Administrateur      compte=hv01   ; hors domaine
SRV-APP   ansible_host=10.0.0.14  ansible_user='ACME\admin-audit'                ; profil détecté

[linux]
SRV-WEB   ansible_host=10.0.0.20  ansible_user=admin  mdp_sudo='...'
PVE01     ansible_host=10.0.0.21  ansible_user=root                ; Proxmox détecté automatiquement

[esxi]
VCENTER   ansible_host=10.0.0.30  ansible_user='audit@vsphere.local'

[reseau]
SW-NETGEAR ansible_host=10.0.0.2  type=switch
[reseau:vars]
snmp_communaute='...'

[unifi]
UNIFI     ansible_host=10.0.0.40  ansible_user=audit-lecture  unifi_port=11443
```

### Mots de passe

- Sans `mdp=` : `lancer_audit.sh` demande **un mot de passe par compte** (les comptes de deux domaines différents donnent deux questions). Ils sont stockés dans un fichier temporaire (droits 600) supprimé à la fin, jamais sur la ligne de commande.
- Avec `mdp='...'` (et `mdp_sudo='...'` pour Linux) sur la ligne ou dans `[windows:vars]` : aucune question. Le fichier `.ini` devient alors sensible.
- `compte=nom` : distingue deux comptes de même nom avec des mots de passe différents (Administrateur local de deux serveurs hors domaine).

### Options par serveur

| Option | Effet |
|---|---|
| `profil=dc_principal,fichiers` | profils du serveur (voir ci-dessous) ; absent = détection automatique |
| `scripts_ajout=32` / `scripts_retrait=21` | ajuster la liste des scripts |
| `audit_apps=false` | pas d'inventaire des applications |
| `audit_ntfs_paths='D:\Partages\Commun;D:\RH'` | chemins NTFS à auditer (sinon tous les partages) |
| `audit_ntfs_depth=2` | profondeur de lecture des droits (défaut 3) |
| `audit_ntfs_size_depth=2` | profondeur du détail des tailles (défaut 5) |
| `audit_ntfs_exclure='Archives;Scans'` | partages exclus (SYSVOL / NETLOGON le sont toujours) |
| `audit_groupes_replmeta=0` | 33_ : sans date de dernière modification des membres (gros domaines) |
| `detail_conteneurs=true` | Linux : paquets installés dans chaque conteneur |
| `unifi_port`, `unifi_site` | contrôleur UniFi : port (443 / 11443 / 8443) et site |

---

## Profils : quels scripts sur quels serveurs

Définis dans `profils.yml`. Un serveur peut cumuler plusieurs profils (`profil=dc,fichiers`).

| Profil | Scripts | Usage |
|---|---|---|
| `poste` | 10, 11, 22 | poste de travail |
| `serveur` | 10, 11, 21 | serveur membre |
| `fichiers` | 10, 11, 31 | serveur de fichiers (NTFS) |
| `hyperv` (alias `hv`) | 10, 11, 20 | hôte Hyper-V |
| `dc` | 21, 30 | DC secondaire |
| `dc_principal` | 10, 11, 13, 21, 30, 31–37 | **un seul par domaine** : collecte les données du domaine |

Sans profil, il est déduit du rôle réel : poste / serveur / DC, `dc_principal` pour l'émulateur PDC, `hyperv` si le service Hyper-V existe, `fichiers` si le serveur partage des dossiers.

> Un deuxième `dc_principal` dans le même domaine collecte tout en double et rallonge fortement l'audit. Le playbook le signale dès le début (« ATTENTION <domaine> : 2 DC principaux… »).

---

## Lancer un audit

```bash
cd ~/Anzoditor
./lancer_audit.sh ACME
```

1. Contrôle des outils (SNMP, pyVmomi selon l'inventaire) et saisie des mots de passe manquants.
2. Microsoft 365 / Google Workspace si configurés (connexion par code ou par lien, avec un compte administrateur du client).
3. **Windows**, en parallèle : détection du rôle, copie des scripts dans `C:\Windows\Temp\Audit_<date>`, **phase 1** (scripts du profil), inventaire des applications, rapatriement, **phase 2** (`33_Audit_Groupes`, qui croise les groupes AD avec les droits NTFS de *tous* les serveurs), nettoyage du dossier distant.
4. **Linux**, VMware, SNMP, UniFi.
5. **Synthèse** dans WSL : `statut.csv`, fusion des applications, Excel, `Synthese_Audit.xlsx`.

Ansible avance étape par étape : chaque étape attend que **tous** les serveurs aient fini la précédente. Un serveur lent (gros partage NTFS) retarde donc les autres. C'est normal.

### Variantes

```bash
./lancer_audit.sh ACME --limit DC01,SRV-FIC,localhost    # quelques serveurs (garder localhost)
./lancer_audit.sh ACME --limit 'linux,localhost'         # uniquement les Linux
./lancer_audit.sh ACME -e audit_apps=false               # sans inventaire des applications
./lancer_audit.sh ACME -e keep_remote=true               # garder C:\Windows\Temp\Audit_* (diagnostic)
SANS_M365=1 SANS_GWS=1 ./lancer_audit.sh ACME            # sans les audits cloud
```

### Régénérer les Excel d'un rapport

```bash
cd rapports/<date>_ACME_audit
python3 Process_excels.py --force
```

---

## Suivre un audit en cours

Dans un second terminal :

```bash
./suivi_audit.sh ACME                 # état à l'instant T
./suivi_audit.sh ACME --boucle 30     # rafraîchi toutes les 30 s (Ctrl+C pour quitter)
./suivi_audit.sh ACME --limit SRV-FIC --lignes 6
```

```
=== Suivi de l'audit ACME - 15:42:10 ===
SRV-FIC : EN COURS -> 31_Audit_NTFS.ps1 depuis 0 h 41 min
      | droits : 41000 dossier(s), 398211 ACE, 00:38:13 - D:\Partages\Compta\...
DC01 : termine / en attente des autres (dernier journal : 37_Audit_GPO_Securite.log (15:07))
PVE01 : aucun script d audit en cours
```

Lecture seule : rien n'est modifié sur les serveurs. Pour voir rapidement les connexions encore ouvertes : `ss -tn state established '( dport = :5985 or dport = :22 )'`.

---

## Résultats

```
rapports/<AAAAMMJJ_HHMM>_<CLIENT>_audit/
├─ statut.csv                 une ligne par serveur : profils, scripts, erreurs, statut
├─ Temp_CSV/<serveur>/        CSV bruts (Comptes, AD, HV, VM, NTFS…)
├─ Temp_CSV/APP|RESEAU|VIRTU|M365|GWS/
├─ logs/<serveur>/            journal de chaque script
└─ Excel/
    ├─ <serveur>_Audit_*.xlsx   un classeur par thème (feuilles + Légende)
    ├─ Audit_Reseau.xlsx, Audit_M365.xlsx, …
    ├─ *_Audit_NTFS_Arborescence.html   schéma interactif des droits
    └─ Synthese_Audit.xlsx
```

Statuts de `statut.csv` : `OK`, `PARTIEL` (un script en erreur), `OK SANS SUDO` (Linux, données limitées, raison dans `logs/<serveur>/sudo.log`), `INJOIGNABLE`, `ERREUR …`.

Les Excel s'ouvrent de préférence depuis une copie Windows : ouverts depuis `\\wsl.localhost`, ils passent en mode protégé et les formules de la synthèse ne sont pas calculées.

---

## Synthèse client

`Synthese_Audit.xlsx` est la restitution :

- **Synthèse** (une page imprimable) : note globale A à E, note par domaine (comptes, mots de passe, groupes, GPO, partages, infrastructure, réseau), 5 priorités.
- **Plan d'action** : constats triés par urgence, avec la raison et l'action recommandée.
- **Durcissement** : référentiel GPO, accès conditionnel Entra ID et protections Intune, mesure par mesure (en place / partiel / manquant).
- **Indicateurs** : toutes les valeurs, seuils et détails ; le statut est modifiable avant restitution.
- **Inventaire**, **Applications web**, **Méthode**.

Les seuils se règlent dans `SEUILS` en tête de `framework/Synthese_audit.py`.

---

## Ports et comptes nécessaires

Depuis le poste d'audit (VPN du client en général) :

| Cible | Port | Compte |
|---|---|---|
| Windows | TCP 5985 (WinRM HTTP, NTLM) | administrateur ; administrateur du domaine pour les DC |
| Linux | TCP 22 | compte avec shell, sudo recommandé |
| vCenter / ESXi | TCP 443 | rôle « Lecture seule » |
| Switchs / bornes | UDP 161 | communauté SNMP (v2c) ou utilisateur SNMPv3 |
| Contrôleur UniFi | TCP 443 / 11443 / 8443 | compte **local** « View Only » (pas de compte UI.com avec MFA) |
| Microsoft 365 | HTTPS sortant | administrateur global (consentement aux autorisations en lecture la première fois) |
| Google Workspace | HTTPS sortant | super administrateur, ou compte de service avec délégation |

Les scripts Windows tournent sous le compte d'audit (runas), ce qui évite le problème de double saut pour les partages distants et DFS.

---

## Dépannage

| Symptôme | Cause probable |
|---|---|
| `ntlm: the specified credentials were rejected` | mauvais compte ou domaine ; compte local → `compte=` + `mdp=` |
| `Connection to … port=5985 timed out` | WinRM non activé ou port filtré (`winrm quickconfig`) |
| `Permission denied (publickey,password)` (Linux) | compte SSH ou mot de passe |
| `Incorrect sudo password` / `OK SANS SUDO` | `mdp_sudo='...'` sur la ligne du serveur |
| Audit très long, rien ne bouge | un serveur NTFS volumineux : `./suivi_audit.sh CLIENT --boucle 30`, réduire `audit_ntfs_depth` |
| Données de domaine en double | plusieurs `dc_principal` dans le même domaine |
| Feuille Excel sans les nouvelles colonnes | supprimer `framework/Templates_Excel/` (régénéré au prochain lancement) |
| `Killed` pendant la génération des Excel | mémoire WSL insuffisante (gros CSV NTFS) : augmenter `memory=` dans `%UserProfile%\.wslconfig` |

Les erreurs complètes sont dans la sortie d'Ansible et dans `rapports/<…>/logs/<serveur>/`.

---

## Ajouter un script

1. **PowerShell** : `framework/Scripts/PowerShell/NN_Audit_Nom.ps1`, ASCII ou UTF-8 avec BOM, non interactif quand `AUDIT_NONINTERACTIVE=1`. Il écrit `$env:COMPUTERNAME.<domaine>_Audit_<Nom>.csv` dans le dossier `$env:AUDIT_TEMP_<COMPTES|AD|HV|VM|NTFS>`.
2. **Profil** : ajouter le numéro `NN` au(x) profil(s) voulus dans `profils.yml`.
3. **Modèle Excel** : `framework/Scripts/Python/TemplateAuditNom.py` (en-têtes = colonnes du CSV, accents via `header_map`).
4. **`modules_config.json`** : motif du CSV, modèle, feuille, éventuellement `classeur` pour regrouper plusieurs CSV.
5. **Synthèse** (facultatif) : un indicateur dans `Synthese_audit.py`.

Un script préfixé par `_` est ignoré.

---

## Sécurité et confidentialité

- **Ne jamais committer** `clients/*.ini` (sauf `EXEMPLE.ini`) ni `rapports/` : ils contiennent des adresses, des comptes, parfois des mots de passe, et l'état de sécurité du client. Le `.gitignore` du dépôt les exclut.
- `chmod 600 clients/*.ini` ; ne pas copier ces fichiers hors de WSL ni dans un dossier synchronisé.
- Les audits sont en lecture seule. Côté Windows, le seul ajout est le dossier temporaire `C:\Windows\Temp\Audit_<date>`, supprimé en fin d'audit (sauf `-e keep_remote=true`).
- Les secrets lus pendant l'audit (clés Wi-Fi, mots de passe d'appareils, clés BitLocker) ne sont jamais écrits dans les rapports.
- Un audit ne se lance qu'avec l'accord écrit du client.

---

## Licence

Usage interne Netoptima. Toute redistribution doit mentionner l'auteur original.