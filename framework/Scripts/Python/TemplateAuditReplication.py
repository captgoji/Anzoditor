import os

# Repertoire de sortie :
#   - AUDIT_TEMPLATES_DIR si defini (appel depuis init.ps1)
#   - Sinon : dossier Templates_Excel a la racine du framework (2 niveaux au-dessus de Scripts/Python)
_script_dir   = os.path.dirname(os.path.abspath(__file__))
_root_dir     = os.path.normpath(os.path.join(_script_dir, '..', '..'))
_default_dir  = os.path.join(_root_dir, 'Templates_Excel')
output_dir    = os.environ.get('AUDIT_TEMPLATES_DIR', _default_dir)
os.makedirs(output_dir, exist_ok=True)

output_file = os.path.join(output_dir, "Template_Audit_Replication.xlsx")

# sinon dossier Templates_Excel a cote du script (execution manuelle)

# sinon ecrit dans le meme dossier que ce script (execution manuelle)
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.worksheet.datavalidation import DataValidation
from openpyxl.worksheet.table import Table, TableStyleInfo

wb = Workbook()

# Feuille 1 : Replication
ws = wb.active
ws.title = "Replication"

headers = [
    "Nom VM",                   # A
    "Replication",              # B
    "Cible de la replication",  # C
    "Statut derniere repl",     # D
    "Nb erreurs replication",   # E
]

for col, header in enumerate(headers, start=1):
    cell = ws.cell(row=1, column=col, value=header)
    cell.font = Font(bold=True, color="FFFFFF", name="Arial")
    cell.fill = PatternFill("solid", fgColor="4F81BD")
    cell.alignment = Alignment(horizontal="center", vertical="center")
    ws.column_dimensions[cell.column_letter].width = 25

ws.column_dimensions["E"].width = 15

table = Table(displayName="Table_Replication", ref="A1:E50")
style = TableStyleInfo(
    name="TableStyleMedium9", showFirstColumn=False,
    showLastColumn=False, showRowStripes=True, showColumnStripes=False)
table.tableStyleInfo = style
ws.add_table(table)

# Feuille 2 : Référentiels
ref = wb.create_sheet("Référentiels")

repl_list   = ["Oui", "Non"]
statut_list = ["OK", "Erreur", "Injoignable", "N/A"]

ref.append(["Replication"] + repl_list)
ref.append(["Statut"]      + statut_list)

# Listes déroulantes
dv_repl = DataValidation(type="list", formula1="Référentiels!$B$1:$C$1", allow_blank=True)
ws.add_data_validation(dv_repl)
dv_repl.add("B2:B50")

dv_statut = DataValidation(type="list", formula1="Référentiels!$B$2:$E$2", allow_blank=True)
ws.add_data_validation(dv_statut)
dv_statut.add("D2:D50")

wb.save(output_file)
print(f"Fichier généré : {output_file}")