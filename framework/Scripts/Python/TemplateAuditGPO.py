# TemplateAuditGPO.py
# Version      : 1.2
# Derniere modif : Feuilles "Référentiel sécurité" et "Paramètres GPO" (37_Audit_GPO_Securite.ps1)
# v1.1         : Colonne Delegation (droits de modification accordes hors administrateurs)
# Role         : Genere Template_Audit_GPO.xlsx
import os

# Repertoire de sortie :
#   - AUDIT_TEMPLATES_DIR si defini (appel depuis init.ps1)
#   - Sinon : dossier Templates_Excel a la racine du framework (2 niveaux au-dessus de Scripts/Python)
_script_dir   = os.path.dirname(os.path.abspath(__file__))
_root_dir     = os.path.normpath(os.path.join(_script_dir, '..', '..'))
_default_dir  = os.path.join(_root_dir, 'Templates_Excel')
output_dir    = os.environ.get('AUDIT_TEMPLATES_DIR', _default_dir)
os.makedirs(output_dir, exist_ok=True)

output_file = os.path.join(output_dir, "Template_Audit_GPO.xlsx")

from openpyxl import Workbook
from openpyxl.formatting.rule import CellIsRule, FormulaRule
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.worksheet.datavalidation import DataValidation
from openpyxl.worksheet.table import Table, TableStyleInfo
from openpyxl.utils import get_column_letter

wb = Workbook()
ws = wb.active
ws.title = "GPO"

# Titre fusionné ligne 1
ws.merge_cells("A1:I1")
title_cell = ws["A1"]
title_cell.value = "GPO"
title_cell.font = Font(bold=True, size=14, name="Arial")
title_cell.alignment = Alignment(horizontal="center", vertical="center")
title_cell.fill = PatternFill("solid", fgColor="C6EFCE")
ws.row_dimensions[1].height = 28

# En-têtes ligne 2 (vide - séparation visuelle)
ws.row_dimensions[2].height = 6

# En-têtes ligne 3
headers = [
    "Domaine",          # A - rempli par le script
    "Nom",              # B - rempli par le script
    "Créé par",         # C - rempli par le script
    "Date de création", # D - rempli par le script
    "OUs liées",        # E - rempli par le script
    "Activé",           # F - rempli par le script
    "Délégation",       # G - rempli par le script
    "Description",      # H - manuel
    "Utilité",          # I - manuel
]

col_widths = [20, 40, 25, 20, 50, 12, 45, 40, 15]

HEADER_FILL  = "4CAF50"   # vert foncé
HEADER_FONT  = "FFFFFF"

for col, (header, width) in enumerate(zip(headers, col_widths), start=1):
    cell = ws.cell(row=3, column=col, value=header)
    cell.font = Font(bold=True, color=HEADER_FONT, name="Arial", size=10)
    cell.fill = PatternFill("solid", fgColor=HEADER_FILL)
    cell.alignment = Alignment(horizontal="center", vertical="center")
    ws.column_dimensions[get_column_letter(col)].width = width

ws.row_dimensions[3].height = 20

# Tableau structuré A3:I103
table = Table(displayName="Table_GPO", ref="A3:I103")
style = TableStyleInfo(
    name="TableStyleMedium7",   # vert clair, cohérent avec la capture
    showFirstColumn=False, showLastColumn=False,
    showRowStripes=True, showColumnStripes=False)
table.tableStyleInfo = style
ws.add_table(table)

# Figer ligne 3 (en-têtes)
ws.freeze_panes = "A4"

# Feuille Référentiels
ref = wb.create_sheet("Référentiels")
oui_non = ["Oui", "Non"]
ref.append(["Activé"] + oui_non)

# Liste déroulante colonne F (Activé)
dv_actif = DataValidation(type="list", formula1="Référentiels!$B$1:$C$1", allow_blank=True)
ws.add_data_validation(dv_actif)
dv_actif.add("F4:F103")

# ─── Référentiel de durcissement (37_Audit_GPO_Securite.ps1) ───
ROUGE = dict(fill=PatternFill("solid", fgColor="FFC7CE"), font=Font(bold=True, color="9C0006"))
ORANGE = dict(fill=PatternFill("solid", fgColor="FFEB9C"), font=Font(bold=True, color="9C5700"))
VERT = dict(fill=PatternFill("solid", fgColor="C6EFCE"), font=Font(bold=True, color="006100"))
GRIS = dict(fill=PatternFill("solid", fgColor="EDEDED"), font=Font(color="595959"))
FIN = 5000


def feuille(nom, colonnes):
    f = wb.create_sheet(nom)
    for i, (t, w) in enumerate(colonnes, start=1):
        c = f.cell(row=1, column=i, value=t)
        c.font = Font(bold=True, color=HEADER_FONT, name="Arial", size=10)
        c.fill = PatternFill("solid", fgColor=HEADER_FILL)
        c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        f.column_dimensions[get_column_letter(i)].width = w
    f.freeze_panes = "B2"
    return f


rs = feuille("Référentiel sécurité", [("Mesure", 32), ("Catégorie", 20), ("Niveau", 11), ("Statut", 24),
                                      ("Valeur constatée", 45), ("Valeur attendue", 45), ("GPO", 30), ("Liaisons", 30),
                                      ("Criticité", 9), ("Détail", 60), ("Recommandation", 70)])
for v, st in (("En place", VERT), ("Partiel", ORANGE), ("Non conforme", ROUGE), ("Absent", ROUGE),
              ("Configure mais non applique", ORANGE)):
    rs.conditional_formatting.add(f"D2:D{FIN}", CellIsRule(operator="equal", formula=[f'"{v}"'], **st))
rs.conditional_formatting.add(f"D2:D{FIN}", FormulaRule(formula=['LEFT($D2,13)="Absent (defau"'], **GRIS))

feuille("Paramètres GPO", [("GPO", 30), ("État GPO", 18), ("Appliquée", 9), ("Liens", 30), ("Portée", 11),
                           ("Source", 20), ("Clé", 70), ("Valeur", 30), ("Donnée", 40)])

lg = wb.create_sheet("Légende référentiel")
for l in [("Statut", "Signification"),
          ("En place", "Une GPO active et liée applique la valeur attendue (voir les OU de liaison)"),
          ("Partiel", "Une partie seulement des paramètres attendus est configurée"),
          ("Non conforme", "Le paramètre est configuré avec une valeur trop faible"),
          ("Configure mais non applique", "Paramètre présent dans une GPO désactivée ou liée nulle part"),
          ("Absent", "Aucune GPO ne configure la mesure"),
          ("Absent (defaut sur)", "Non configuré, mais la valeur par défaut des Windows récents est sûre"),
          ("Méthode", "Le contenu des GPO est lu dans SYSVOL (Registry.pol, GptTmpl.inf, audit.csv, préférences) : "
                      "les noms des GPO ne sont pas pris en compte. Référentiel : gpo.md (+ compléments Netoptima)")]:
    lg.append(l)
lg.column_dimensions["A"].width = 30
lg.column_dimensions["B"].width = 120

wb.save(output_file)
print(f"Fichier généré : {output_file}")
