import os

# Repertoire de sortie :
#   - AUDIT_TEMPLATES_DIR si defini (appel depuis init.ps1 / Process_excels.py)
#   - Sinon : dossier Templates_Excel a la racine du framework (2 niveaux au-dessus de Scripts/Python)
# v1.2 : ajout Fabricant, Modèle, S/N (20_Audit_Hyperviseurs v1.5)
# v1.1 : ajout des colonnes Nom du cluster, Nb VM démarrées, VMs hébergées (20_Audit_Hyperviseurs v1.4)
_script_dir   = os.path.dirname(os.path.abspath(__file__))
_root_dir     = os.path.normpath(os.path.join(_script_dir, '..', '..'))
_default_dir  = os.path.join(_root_dir, 'Templates_Excel')
output_dir    = os.environ.get('AUDIT_TEMPLATES_DIR', _default_dir)
os.makedirs(output_dir, exist_ok=True)

output_file = os.path.join(output_dir, "Template_Audit_Hyperviseurs.xlsx")

from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.datavalidation import DataValidation
from openpyxl.worksheet.table import Table, TableStyleInfo

wb = Workbook()

# Feuille 1 : Hyperviseurs
ws = wb.active
ws.title = "Hyperviseurs"

headers = [
    "Nom",                  # A
    "IP (Physique)",        # B
    "IP (vEthernet)",       # C
    "Adresse MAC",          # D
    "Rôles",                # E
    "Type d'hyperviseur",   # F
    "OS",                   # G
    "Intégré au domaine",   # H
    "Nom de Domaine",       # I
    "Cluster/Standalone",   # J
    "Nom du cluster",       # K
    "Processeurs",          # L
    "RAM",                  # M
    "Stockage",             # N
    "Nb VM hébergées",      # O
    "Nb VM démarrées",      # P
    "VMs hébergées",        # Q
    "Fabricant",            # R
    "Modèle",               # S
    "S/N",                  # T
]
derniere = get_column_letter(len(headers))

for col, header in enumerate(headers, start=1):
    cell = ws.cell(row=1, column=col, value=header)
    cell.font = Font(bold=True, color="FFFFFF", name="Arial")
    cell.fill = PatternFill("solid", fgColor="4F81BD")
    cell.alignment = Alignment(horizontal="center", vertical="center")
    ws.column_dimensions[get_column_letter(col)].width = 25
ws.column_dimensions["Q"].width = 60

table = Table(displayName="Table_Hyperviseurs", ref=f"A1:{derniere}10")
table.tableStyleInfo = TableStyleInfo(
    name="TableStyleMedium9", showFirstColumn=False,
    showLastColumn=False, showRowStripes=True, showColumnStripes=False)
ws.add_table(table)

# Feuille 2 : Référentiels
ref = wb.create_sheet("Référentiels")

hyperviseur_types = ["VMware ESXi", "Microsoft Hyper-V", "Proxmox VE", "XenServer", "Nutanix AHV", "Autre"]
os_list           = ["Windows Server 2016", "Windows Server 2019", "Windows Server 2022", "Windows Server 2025",
                     "Linux Ubuntu", "Linux Debian", "Linux RHEL", "ESXi", "Autre"]
domain_list       = ["Oui", "Non"]
cluster_list      = ["Cluster", "Standalone"]

ref.append(["Type d'hyperviseur"] + hyperviseur_types)
ref.append(["OS"]                 + os_list)
ref.append(["Intégré au domaine"] + domain_list)
ref.append(["Cluster/Standalone"] + cluster_list)

# Listes déroulantes (OS sans liste : la valeur collectée est le libellé complet de Windows)
for formule, plage in [("Référentiels!$B$1:$G$1", "F2:F10"),
                       ("Référentiels!$B$3:$C$3", "H2:H10"),
                       ("Référentiels!$B$4:$C$4", "J2:J10")]:
    dv = DataValidation(type="list", formula1=formule, allow_blank=True)
    ws.add_data_validation(dv)
    dv.add(plage)

wb.save(output_file)
print(f"Fichier généré : {output_file}")
