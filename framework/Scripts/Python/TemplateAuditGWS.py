# TemplateAuditGWS.py
# Version      : 1.0
# Derniere modif : Creation
# Role         : Genere Template_Audit_GWS.xlsx pour Scripts/GoogleWorkspace/Audit_GWS.py
#                (Temp_CSV/GWS/<client>_Audit_GWS_*.csv), classeur Excel/Audit_Google_Workspace.xlsx
import os

from openpyxl import Workbook
from openpyxl.formatting.rule import CellIsRule
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

_script_dir = os.path.dirname(os.path.abspath(__file__))
_root_dir = os.path.normpath(os.path.join(_script_dir, '..', '..'))
output_dir = os.environ.get('AUDIT_TEMPLATES_DIR', os.path.join(_root_dir, 'Templates_Excel'))
os.makedirs(output_dir, exist_ok=True)
output_file = os.path.join(output_dir, "Template_Audit_GWS.xlsx")

ENTETE = (Font(bold=True, color="FFFFFF", name="Arial"), PatternFill("solid", fgColor="4F81BD"))
ROUGE = dict(fill=PatternFill("solid", fgColor="FFC7CE"), font=Font(bold=True, color="9C0006"))
ORANGE = dict(fill=PatternFill("solid", fgColor="FFEB9C"), font=Font(bold=True, color="9C5700"))
VERT = dict(fill=PatternFill("solid", fgColor="C6EFCE"), font=Font(bold=True, color="006100"))
FIN = 20000
FEUILLES = {
    "Comptes": [("Email", 32), ("Nom", 22), ("Unité organisationnelle", 22), ("Actif", 7), ("Archivé", 8),
                ("Super admin", 9), ("Admin délégué", 9), ("Rôles admin", 30), ("Créé le", 17),
                ("Dernière connexion", 17), ("Jamais connecté", 9), ("Inactif 90 j", 9),
                ("Validation en 2 étapes", 11), ("2 étapes imposée", 10), ("MDP à changer", 9)],
    "Rôles admin": [("Rôle", 34), ("Membre", 22), ("Email", 32), ("Type", 12), ("Actif", 7),
                    ("Validation en 2 étapes", 11), ("Dernière connexion", 17), ("Portée", 12)],
    "Groupes": [("Email", 34), ("Nom", 28), ("Membres directs", 10), ("Description", 60)],
    "Sécurité": [("Paramètre", 50), ("Valeur", 30), ("Statut", 11), ("Commentaire", 90)],
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
    r = lambda t, v, st: ws.conditional_formatting.add(f"{L[t]}2:{L[t]}{FIN}",
                                                         CellIsRule(operator="equal", formula=[f'"{v}"'], **st))
    if "Validation en 2 étapes" in L:
        r("Validation en 2 étapes", "Non", ROUGE)
        r("Validation en 2 étapes", "Oui", VERT)
    if nom == "Comptes":
        r("Inactif 90 j", "Oui", ORANGE)
        r("Super admin", "Oui", dict(font=Font(bold=True, color="9C0006")))
    if nom == "Rôles admin":
        r("Rôle", "Super administrateur", dict(font=Font(bold=True, color="9C0006")))
    if nom == "Sécurité":
        for v, st in (("Critique", ROUGE), ("Attention", ORANGE), ("OK", VERT)):
            r("Statut", v, st)
wl = wb.create_sheet("Legende")
for l in [("Élément", "Signification"),
          ("Source", "Admin SDK Directory API en lecture seule (Audit_GWS.py) : compte de service avec délégation "
                     "au niveau du domaine, ou connexion navigateur avec un super administrateur"),
          ("Validation en 2 étapes", "isEnrolledIn2Sv : l'utilisateur a enregistré une seconde méthode ; "
                                     "« imposée » = la règle de l'unité organisationnelle l'exige"),
          ("Inactif 90 j", "Aucune connexion depuis 90 jours (ou jamais) : compte et licence à revoir"),
          ("Super admin", "Accès total au domaine : 2 à 4 comptes dédiés, tous avec validation en 2 étapes")]:
    wl.append(l)
for c in wl[1]:
    c.font, c.fill = ENTETE
wl.column_dimensions["A"].width = 22
wl.column_dimensions["B"].width = 120
wb.save(output_file)
print(f"Fichier genere : {output_file}")
