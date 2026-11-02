# TemplateAuditLAPS.py
# Version      : 1.0
# Derniere modif : Creation
# Role         : Genere Template_Audit_LAPS.xlsx (feuille LAPS) pour 36_Audit_LAPS.ps1 (AD\<HOTE>_Audit_LAPS.csv)
import os

from openpyxl import Workbook
from openpyxl.formatting.rule import CellIsRule, FormulaRule
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

_script_dir = os.path.dirname(os.path.abspath(__file__))
_root_dir = os.path.normpath(os.path.join(_script_dir, '..', '..'))
output_dir = os.environ.get('AUDIT_TEMPLATES_DIR', os.path.join(_root_dir, 'Templates_Excel'))
os.makedirs(output_dir, exist_ok=True)
output_file = os.path.join(output_dir, "Template_Audit_LAPS.xlsx")

colonnes = [("Ordinateur", 22), ("Type", 20), ("OS", 34), ("Actif", 7), ("Dernière connexion", 18), ("OU", 50),
            ("LAPS", 20), ("Expiration du mot de passe", 20), ("Alerte", 60)]
wb = Workbook()
ws = wb.active
ws.title = "LAPS"
for i, (t, l) in enumerate(colonnes, start=1):
    c = ws.cell(row=1, column=i, value=t)
    c.font, c.fill = Font(bold=True, color="FFFFFF", name="Arial"), PatternFill("solid", fgColor="4F81BD")
    c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
    ws.column_dimensions[get_column_letter(i)].width = l
ws.freeze_panes = "B2"
ws.conditional_formatting.add("G2:G20000", CellIsRule(operator="equal", formula=['"Aucun"'],
                              fill=PatternFill("solid", fgColor="FFC7CE"), font=Font(bold=True, color="9C0006")))
ws.conditional_formatting.add("G2:G20000", CellIsRule(operator="equal", formula=['"Windows LAPS"'],
                              fill=PatternFill("solid", fgColor="C6EFCE"), font=Font(bold=True, color="006100")))
ws.conditional_formatting.add("I2:I20000", FormulaRule(formula=['LEN($I2)>0'],
                              fill=PatternFill("solid", fgColor="FFEB9C"), font=Font(bold=True, color="9C5700")))
wl = wb.create_sheet("Legende")
for ligne in [("Élément", "Signification"),
              ("LAPS", "Windows LAPS (msLAPS-*) ou LAPS historique (ms-Mcs-AdmPwd*) : mot de passe administrateur "
                       "local unique et renouvelé ; « Aucun » = même mot de passe probable sur plusieurs machines"),
              ("Expiration", "Date de la prochaine rotation ; expirée depuis plus de 7 jours = rotation bloquée "
                             "(GPO absente, machine éteinte, droits)"),
              ("Source", "36_Audit_LAPS.ps1 sur le DC principal ; aucun mot de passe n'est lu")]:
    wl.append(ligne)
wl.column_dimensions["A"].width = 16
wl.column_dimensions["B"].width = 120
wb.save(output_file)
print(f"Fichier genere : {output_file}")
