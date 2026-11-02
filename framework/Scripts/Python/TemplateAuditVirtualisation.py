# TemplateAuditVirtualisation.py
# Version      : 1.0
# Derniere modif : Creation
# Role         : Genere Template_Audit_Virtualisation.xlsx (VM, Stockage, Securite) pour les CSV de
#                Scripts/Virtualisation (Audit_ESXi.py, Audit_Proxmox.pl) : Temp_CSV/VIRTU/*_Audit_Virtu_*.csv,
#                regroupes dans Excel/Audit_Virtualisation.xlsx. Les hotes vont dans le classeur Hyperviseurs.
import os

from openpyxl import Workbook
from openpyxl.formatting.rule import CellIsRule, FormulaRule
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

_script_dir = os.path.dirname(os.path.abspath(__file__))
_root_dir = os.path.normpath(os.path.join(_script_dir, '..', '..'))
output_dir = os.environ.get('AUDIT_TEMPLATES_DIR', os.path.join(_root_dir, 'Templates_Excel'))
os.makedirs(output_dir, exist_ok=True)
output_file = os.path.join(output_dir, "Template_Audit_Virtualisation.xlsx")

ENTETE = (Font(bold=True, color="FFFFFF", name="Arial"), PatternFill("solid", fgColor="4F81BD"))
ROUGE = dict(fill=PatternFill("solid", fgColor="FFC7CE"), font=Font(bold=True, color="9C0006"))
ORANGE = dict(fill=PatternFill("solid", fgColor="FFEB9C"), font=Font(bold=True, color="9C5700"))
VERT = dict(fill=PatternFill("solid", fgColor="C6EFCE"), font=Font(bold=True, color="006100"))
FIN = 20000
FEUILLES = {
    "VMs": [("Hyperviseur", 18), ("Hôte", 16), ("VM", 24), ("ID", 8), ("Type", 10), ("État", 10), ("OS", 22),
            ("vCPU", 6), ("RAM (Go)", 8), ("Disque (Go)", 9), ("Démarrage auto", 9), ("Agent invité", 14),
            ("Version matérielle", 12), ("Snapshots", 8), ("Plus ancien snapshot (j)", 10), ("Dernière sauvegarde", 17),
            ("Sauvegarde planifiée", 12), ("IP", 15), ("Alerte", 60)],
    "Stockage": [("Hyperviseur", 18), ("Hôte", 16), ("Stockage", 20), ("Type", 10), ("Partage", 8),
                 ("Taille (Go)", 10), ("Utilisé (Go)", 10), ("Utilisé (%)", 9), ("Alerte", 30)],
    "Sécurité": [("Hyperviseur", 20), ("Contrôle", 26), ("Valeur", 50), ("Statut", 11), ("Commentaire", 80)],
}
wb = Workbook()
wb.remove(wb.active)
for nom, cols in FEUILLES.items():
    ws = wb.create_sheet(nom)
    L = {}
    for i, (t, w) in enumerate(cols, start=1):
        c = ws.cell(row=1, column=i, value=t)
        c.font, c.fill = ENTETE
        c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        ws.column_dimensions[get_column_letter(i)].width = w
        L[t] = get_column_letter(i)
    ws.freeze_panes = "B2"
    p = lambda t: f"{L[t]}2:{L[t]}{FIN}"
    if "Alerte" in L:
        ws.conditional_formatting.add(p("Alerte"), FormulaRule(formula=[f'LEN(${L["Alerte"]}2)>0'], **ORANGE))
    if nom == "VMs":
        ws.conditional_formatting.add(p("Sauvegarde planifiée"), CellIsRule(operator="equal", formula=['"Non"'], **ROUGE))
        ws.conditional_formatting.add(p("Plus ancien snapshot (j)"), CellIsRule(operator="greaterThan", formula=['7'], **ORANGE))
    if nom == "Stockage":
        ws.conditional_formatting.add(p("Utilisé (%)"), CellIsRule(operator="greaterThan", formula=['85'], **ROUGE))
    if nom == "Sécurité":
        for v, st in (("Critique", ROUGE), ("Attention", ORANGE), ("OK", VERT)):
            ws.conditional_formatting.add(p("Statut"), CellIsRule(operator="equal", formula=[f'"{v}"'], **st))
wl = wb.create_sheet("Legende")
for l in [("Élément", "Signification"),
          ("Sources", "VMware : API vSphere en lecture seule (Audit_ESXi.py, ESXi isolé ou vCenter). "
                      "Proxmox VE : pvesh sur chaque nœud (Audit_Proxmox.pl). Les hôtes figurent dans les classeurs Hyperviseurs."),
          ("Sauvegarde planifiée", "Proxmox : VM couverte par une tâche de sauvegarde ; VMware : non relevé (Veeam, etc.)"),
          ("Snapshots", "Un snapshot de plus de 7 jours dégrade les performances et n'est pas une sauvegarde"),
          ("Version", "Comparée à la fin de support éditeur (table en tête des scripts, à mettre à jour)"),
          ("Accès SSH / ESXi Shell", "À n'activer que le temps d'une intervention ; mode verrouillage conseillé avec vCenter")]:
    wl.append(l)
for c in wl[1]:
    c.font, c.fill = ENTETE
wl.column_dimensions["A"].width = 22
wl.column_dimensions["B"].width = 120
wb.save(output_file)
print(f"Fichier genere : {output_file}")
