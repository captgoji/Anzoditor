# TemplateAuditReseau.py
# Version      : 1.2
# Derniere modif : Controleur UniFi (Scripts/Reseau/Audit_UniFi.py) : feuille VLAN, colonnes Profil / PoE /
#                  Reseaux tagues / Securite du port, Wi-Fi (VLAN, actif, alerte), equipements (firmware a jour,
#                  fin de vie, source)
# v1.1         : Feuille Ports : Mode (Access / Trunk / Hybride), VLANs non tagués / tagués, voisin LLDP
# Role         : Genere Template_Audit_Reseau.xlsx pour les CSV de Scripts/Reseau/Audit_Reseau_SNMP.py
#                (Temp_CSV/RESEAU/<equipement>_Audit_Reseau[_Ports|_Voisins|_Wifi|_Controles].csv),
#                regroupes dans un seul classeur Excel/Audit_Reseau.xlsx (modules_config.json).
# NB           : en-tetes = colonnes du CSV apres header_map (accents ajoutes par modules_config.json).
import os

from openpyxl import Workbook
from openpyxl.formatting.rule import CellIsRule, FormulaRule
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.datavalidation import DataValidation

_script_dir = os.path.dirname(os.path.abspath(__file__))
_root_dir = os.path.normpath(os.path.join(_script_dir, '..', '..'))
output_dir = os.environ.get('AUDIT_TEMPLATES_DIR', os.path.join(_root_dir, 'Templates_Excel'))
os.makedirs(output_dir, exist_ok=True)
output_file = os.path.join(output_dir, "Template_Audit_Reseau.xlsx")

ENTETE_FONT = Font(bold=True, color="FFFFFF", name="Arial")
ENTETE_FILL = PatternFill("solid", fgColor="4F81BD")
ROUGE = (PatternFill("solid", fgColor="FFC7CE"), Font(bold=True, color="9C0006"))
ORANGE = (PatternFill("solid", fgColor="FFEB9C"), Font(bold=True, color="9C5700"))
VERT = (PatternFill("solid", fgColor="C6EFCE"), Font(bold=True, color="006100"))
FIN = 5000

FEUILLES = {
    "Equipements": [("Équipement", 20), ("IP", 15), ("Type", 13), ("Marque", 16), ("Modèle", 22), ("Firmware", 16),
                    ("S/N", 20), ("Nom SNMP", 18), ("Description", 40), ("Localisation", 18), ("Contact", 18),
                    ("Uptime", 11), ("Dernier redémarrage", 14), ("Version SNMP", 9), ("Communauté par défaut", 13),
                    ("Telnet", 8), ("HTTP", 8), ("HTTPS", 8), ("SSH", 8), ("Ports physiques", 9),
                    ("Ports connectés", 9), ("Ports actifs non connectés", 11), ("VLANs", 30), ("Voisins LLDP", 30),
                    ("Firmware à jour", 10), ("Fin de vie", 9), ("Source", 16), ("Statut", 18), ("Alerte", 60)],
    "Ports": [("Équipement", 20), ("Port", 14), ("Description", 30), ("Alias", 25), ("Type", 12), ("Admin", 10),
              ("État", 12), ("Vitesse (Mb/s)", 10), ("Mode", 10), ("VLAN natif", 14), ("VLANs non tagués", 16),
              ("VLANs tagués", 22), ("Réseaux tagués", 30), ("Profil", 16), ("PoE", 12), ("Sécurité du port", 14),
              ("Voisin LLDP", 30), ("Alerte", 40)],
    "VLAN": [("Contrôleur", 18), ("Site", 14), ("VLAN", 7), ("Nom", 20), ("Usage", 22), ("Sous-réseau", 18),
             ("DHCP", 26), ("Isolation", 9), ("Accès Internet", 9), ("IGMP snooping", 9),
             ("Ports connectés en natif", 10), ("Ports connectés tagués", 10), ("SSID", 25), ("Alerte", 40)],
    "Voisins LLDP": [("Équipement", 20), ("Port local", 16), ("Voisin", 25), ("Port voisin", 20),
                     ("Description port voisin", 30), ("Chassis voisin", 20)],
    "Wi-Fi": [("Équipement", 20), ("SSID", 28), ("Chiffrement", 16), ("Réseau invité isolé", 14), ("VLAN", 16),
              ("Actif", 7), ("Commentaire", 50), ("Alerte", 40)],
    "Points à vérifier": [("Équipement", 20), ("IP", 15), ("Type", 13), ("Point de contrôle", 60), ("Résultat", 12),
                          ("Commentaire", 50)],
}

wb = Workbook()
wb.remove(wb.active)
for nom, colonnes in FEUILLES.items():
    ws = wb.create_sheet(nom)
    for i, (titre, largeur) in enumerate(colonnes, start=1):
        c = ws.cell(row=1, column=i, value=titre)
        c.font, c.fill = ENTETE_FONT, ENTETE_FILL
        c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        ws.column_dimensions[get_column_letter(i)].width = largeur
    ws.freeze_panes = "B2"
    lettre = {t: get_column_letter(i) for i, (t, _) in enumerate(colonnes, start=1)}
    if "Alerte" in lettre:
        L = lettre["Alerte"]
        ws.conditional_formatting.add(f"{L}2:{L}{FIN}", FormulaRule(formula=[f'LEN(${L}2)>0'], fill=ROUGE[0], font=ROUGE[1]))
    if nom == "Equipements":
        for col, (fill, font) in (("Telnet", ROUGE), ("HTTP", ORANGE)):
            L = lettre[col]
            ws.conditional_formatting.add(f"{L}2:{L}{FIN}", CellIsRule(operator="equal", formula=['"Oui"'], fill=fill, font=font))
        L = lettre["Communauté par défaut"]
        ws.conditional_formatting.add(f"{L}2:{L}{FIN}", FormulaRule(formula=[f'AND(${L}2<>"",${L}2<>"Non")'], fill=ROUGE[0], font=ROUGE[1]))
        L = lettre["Statut"]
        ws.conditional_formatting.add(f"{L}2:{L}{FIN}", FormulaRule(formula=[f'LEFT(${L}2,5)="INJOI"'], fill=ORANGE[0], font=ORANGE[1]))
    if nom == "Equipements":
        for col in ("Firmware à jour", "Fin de vie"):
            L = lettre[col]
            ws.conditional_formatting.add(f"{L}2:{L}{FIN}", CellIsRule(
                operator="equal", formula=['"Non"' if col == "Firmware à jour" else '"Oui"'], fill=ORANGE[0], font=ORANGE[1]))
    if nom == "Ports":
        for val, couleur in (("Trunk", "DDEBF7"), ("Hybride", "FFEB9C")):
            ws.conditional_formatting.add(f"{lettre['Mode']}2:{lettre['Mode']}{FIN}", CellIsRule(
                operator="equal", formula=[f'"{val}"'], fill=PatternFill("solid", fgColor=couleur), font=Font(bold=True)))
    if nom == "Wi-Fi":
        for col, valeurs in (("Chiffrement", "WPA3,WPA2/WPA3,WPA2,WPA3-Entreprise,WPA2-Entreprise,WPA,WEP,Ouvert,A verifier"),
                             ("Réseau invité isolé", "Oui,Non,Pas de reseau invite,A verifier")):
            dv = DataValidation(type="list", formula1=f'"{valeurs}"', allow_blank=True)
            ws.add_data_validation(dv)
            dv.add(f"{lettre[col]}2:{lettre[col]}{FIN}")
        L = lettre["Chiffrement"]
        for val, (fill, font) in (("Ouvert", ROUGE), ("WEP", ROUGE), ("WPA", ROUGE), ("WPA2", ORANGE), ("WPA3", VERT), ("WPA2/WPA3", VERT),
                                  ("WPA2-Entreprise", VERT), ("WPA3-Entreprise", VERT)):
            ws.conditional_formatting.add(f"{L}2:{L}{FIN}", CellIsRule(operator="equal", formula=[f'"{val}"'], fill=fill, font=font))
    if nom == "Points à vérifier":
        L = lettre["Résultat"]
        dv = DataValidation(type="list", formula1='"Oui,Non,N/A,A verifier"', allow_blank=True)
        ws.add_data_validation(dv)
        dv.add(f"{L}2:{L}{FIN}")
        for val, (fill, font) in (("Oui", VERT), ("Non", ROUGE), ("A verifier", ORANGE)):
            ws.conditional_formatting.add(f"{L}2:{L}{FIN}", CellIsRule(operator="equal", formula=[f'"{val}"'], fill=fill, font=font))

wl = wb.create_sheet("Legende")
for ligne in [
    ("Élément", "Signification"),
    ("Source", "SNMP en lecture seule depuis la machine Ansible (Audit_Reseau_SNMP.py) + test de connexion TCP 22/23/80/443"),
    ("S/N", "ENTITY-MIB (numéro de série du châssis) ; '(non fourni en SNMP)' si l'équipement ne le publie pas"),
    ("Communauté par défaut", "public / private acceptée en plus de la communauté fournie : n'importe qui peut lire la configuration"),
    ("Telnet / HTTP", "Administration sans chiffrement : identifiants lisibles sur le réseau"),
    ("Dernier redémarrage", "Plus d'un an sans redémarrage = firmware probablement jamais mis à jour"),
    ("Ports actifs non connectés", "Ports activés sans câble : à désactiver ou placer dans un VLAN inutilisé"),
    ("VLAN natif", "PVID du port (Q-BRIDGE-MIB) : VLAN des trames reçues sans étiquette ; VLAN 1 partout = pas de segmentation"),
    ("Mode", "Access = un seul VLAN non tagué ; Trunk = au moins un VLAN tagué ; Hybride = plusieurs VLAN non tagués. "
             "Vide si l'équipement ne publie pas la Q-BRIDGE-MIB"),
    ("VLANs tagués / non tagués", "Appartenance du port aux VLAN (configuration statique, sinon état courant)"),
    ("Wi-Fi", "SNMP ne donne que le nom des réseaux : chiffrement et isolation invité à renseigner à la main. "
              "Avec le contrôleur UniFi : chiffrement, VLAN et isolation lus dans la configuration"),
    ("Contrôleur UniFi", "Switchs / bornes UniFi audités par l'API du contrôleur (Audit_UniFi.py, lecture seule) : "
                         "colonne Source = « Controleur UniFi », Version SNMP sans objet"),
    ("Profil", "Profil de port UniFi appliqué ; « Par défaut (All) » ou « All » = tous les VLAN tagués + VLAN 1 natif ; "
               "« Personnalisé » = réglages propres au port"),
    ("VLAN (feuille)", "Réseaux créés dans le contrôleur : ID, sous-réseau, DHCP, isolation, nombre de ports connectés "
                       "qui les transportent (natif / tagué) et SSID associés"),
    ("Firmware à jour / Fin de vie", "Selon le contrôleur UniFi : mise à jour disponible, modèle en fin de vie (EOL) "
                                     "ou en support long terme (LTS)"),
    ("Points à vérifier", "Contrôles impossibles en SNMP, à faire dans l'interface d'administration : Oui / Non / N/A"),
]:
    wl.append(ligne)
for c in wl[1]:
    c.font, c.fill = ENTETE_FONT, ENTETE_FILL
wl.column_dimensions["A"].width = 26
wl.column_dimensions["B"].width = 110

wb.save(output_file)
print(f"Fichier genere : {output_file}")
