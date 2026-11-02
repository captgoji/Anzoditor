# TemplateAuditApplications.py
# Version      : 1.0
# Derniere modif : Creation
# Role         : Genere Template_Audit_Applications.xlsx (feuilles Applications, Alertes, Legende)
#                pour les CSV de CheckApp.ps1 / CheckApp.sh fusionnes par ansible/audit.yml :
#                Temp_CSV\APP\<CLIENT>_Audit_Applications.csv et <CLIENT>_Audit_Applications_Alertes.csv
# NB           : aucune Table pre-dimensionnee : Process_excels.py la pose a la bonne taille apres injection.
#                Les en-tetes sont ceux du CSV traduits par le header_map de modules_config.json
#                (serveur -> Serveur, name -> Application, ...). Les garder identiques aux deux endroits.
import os

from openpyxl import Workbook
from openpyxl.formatting.rule import FormulaRule
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

_script_dir = os.path.dirname(os.path.abspath(__file__))
_root_dir   = os.path.normpath(os.path.join(_script_dir, '..', '..'))
output_dir  = os.environ.get('AUDIT_TEMPLATES_DIR', os.path.join(_root_dir, 'Templates_Excel'))
os.makedirs(output_dir, exist_ok=True)
output_file = os.path.join(output_dir, "Template_Audit_Applications.xlsx")

ENTETE_FONT = Font(bold=True, color="FFFFFF", name="Arial")
ENTETE_FILL = PatternFill("solid", fgColor="4F81BD")
ROUGE  = PatternFill("solid", fgColor="F8D7DA")
ORANGE = PatternFill("solid", fgColor="FFE5CC")
JAUNE  = PatternFill("solid", fgColor="FFF4CC")
VERT   = PatternFill("solid", fgColor="D4EDDA")
GRIS   = PatternFill("solid", fgColor="E7E9ED")
TEXTE_ACTIF = Font(bold=True, color="9C0006")
MAX_LIGNES = 200000

# (en-tete Excel, largeur) - ordre identique aux colonnes du CSV
COLONNES = [
    ("Serveur", 22), ("Application", 38), ("Version", 22), ("Date installation", 19),
    ("Source", 16), ("Editeur / image / chemin", 40), ("Installe par", 22),
    ("Ports en ecoute", 45), ("Exposition", 12), ("Alerte", 60),
]


def lettre(titre):
    return get_column_letter([c[0] for c in COLONNES].index(titre) + 1)


def preparer_feuille(ws):
    for idx, (titre, largeur) in enumerate(COLONNES, start=1):
        cell = ws.cell(row=1, column=idx, value=titre)
        cell.font = ENTETE_FONT
        cell.fill = ENTETE_FILL
        cell.alignment = Alignment(horizontal="center", vertical="center")
        ws.column_dimensions[cell.column_letter].width = largeur
    ws.freeze_panes = "C2"

    fin   = get_column_letter(len(COLONNES))
    ligne = f"A2:{fin}{MAX_LIGNES}"
    a, e, x = lettre("Alerte"), lettre("Source"), lettre("Exposition")
    cf = ws.conditional_formatting
    # Ligne entiere : priorite dans l'ordre d'ajout
    cf.add(ligne, FormulaRule(formula=[f'OR(LEFT(${a}2,10)="VULNERABLE",LEFT(${a}2,10)="FIN DE VIE")'], fill=ROUGE, stopIfTrue=True))
    cf.add(ligne, FormulaRule(formula=[f'LEFT(${a}2,10)="A VERIFIER"'], fill=ORANGE, stopIfTrue=True))
    cf.add(ligne, FormulaRule(formula=[f'LEFT(${a}2,2)="OK"'], fill=VERT, stopIfTrue=True))
    cf.add(ligne, FormulaRule(formula=[f'${e}2="processus"'], fill=GRIS))
    # Cellules ciblees
    cf.add(f"{x}2:{x}{MAX_LIGNES}", FormulaRule(formula=[f'${x}2="RESEAU"'], fill=JAUNE))
    cf.add(f"{a}2:{a}{MAX_LIGNES}", FormulaRule(formula=[f'ISNUMBER(SEARCH("ACTIF",${a}2))'], font=TEXTE_ACTIF))


wb = Workbook()

ws = wb.active
ws.title = "Applications"
preparer_feuille(ws)

wa = wb.create_sheet("Alertes")
preparer_feuille(wa)

# ─── Legende ────────────────────────────────────────────────
wl = wb.create_sheet("Legende")
legende = [
    ("Couleur / colonne", "Signification"),
    ("Rouge", "PHP / Node.js VULNERABLE (version corrigee indiquee) ou en FIN DE VIE (plus de correctif)"),
    ("Orange", "A VERIFIER : version illisible ou branche non listee"),
    ("Vert", "PHP / Node.js a jour (OK), y compris backport distribution trouve dans le changelog"),
    ("Gris", "Processus en ecoute qui ne vient d'aucun paquet / application installee (binaire dans /opt, script maison, service Windows...)"),
    ("Jaune (Exposition)", "Au moins un port en ecoute ailleurs que sur 127.0.0.1 / ::1 (n'implique pas que le pare-feu le laisse passer)"),
    ("Texte rouge gras (Alerte)", "Binaire ACTIF : au moins un processus tourne actuellement avec cet executable"),
    ("", ""),
    ("Feuille Alertes", "Uniquement les lignes PHP / Node.js dont l'alerte n'est pas OK : liste des actions a mener"),
    ("", ""),
    ("Source", "Linux : dpkg, rpm, snap, flatpak, docker:<etat> / podman:<etat> (conteneur), dans:<conteneur> (paquet dans un conteneur)"),
    ("", "Windows : HKLM64, HKLM32 (registre Uninstall machine), HKU (installe dans le profil d'un utilisateur)"),
    ("", "Commun : processus (port sans application), php, nodejs, php:conteneur, nodejs:conteneur, appli-php (WordPress, GLPI, Dolibarr...)"),
    ("Date installation", "Linux : derniere installation OU mise a jour du paquet. Windows : date declaree par l'installeur. Conteneur : date de creation"),
    ("Installe par", "Linux : journaux apt / dnf / yum / zypper (vide si purges ou paquet de l'installation initiale). "
                     "Windows : profil HKU, sinon evenement MsiInstaller 1033, sinon vide"),
    ("Ports en ecoute", "tcp:443 = toutes les interfaces ; tcp:127.0.0.1:5432 = local ; tcp:443->443 = port publie par un conteneur ; "
                        "interne:9200/tcp = joignable seulement depuis les autres conteneurs"),
    ("Exposition", "RESEAU / LOCAL / INTERNE (reseau docker uniquement) ; vide = aucun port"),
    ("Alerte", "PHP : PHP2Shell CVE-2026-109618 (corrige en 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12). "
               "Node.js : CVE-2026-111497 (corrige en 22.23.4 / 24.22.1 / 26.12.1 ; 20.x et avant = fin de vie)"),
    ("", "Debian / Ubuntu / RHEL corrigent souvent sans changer le numero de version : un paquet de distribution VULNERABLE "
         "dont le CVE est absent du changelog local est a verifier a la main"),
]
for ligne in legende:
    wl.append(ligne)
wl["A1"].font = Font(bold=True, name="Arial")
wl["B1"].font = Font(bold=True, name="Arial")
for cell, fill in (("A2", ROUGE), ("A3", ORANGE), ("A4", VERT), ("A5", GRIS), ("A6", JAUNE)):
    wl[cell].fill = fill
wl["A7"].font = TEXTE_ACTIF
for row in wl.iter_rows(min_row=2):
    row[1].alignment = Alignment(wrap_text=True, vertical="top")
    row[0].alignment = Alignment(vertical="top")
wl.column_dimensions["A"].width = 26
wl.column_dimensions["B"].width = 120

wb.save(output_file)
print(f"Fichier genere : {output_file}")
