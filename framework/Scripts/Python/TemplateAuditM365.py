# TemplateAuditM365.py
# Version      : 1.1
# Derniere modif : Feuilles Accès conditionnel, Intune, Référentiel sécurité ; colonnes Intune / BitLocker (Appareils)
# Role         : Genere Template_Audit_M365.xlsx pour les CSV de Scripts/M365/Audit_M365.py
#                (Temp_CSV/M365/<client>_Audit_Comptes_365.csv et _Audit_M365_*.csv), classeur Excel/Audit_M365.xlsx
# NB           : en-tetes = colonnes CSV apres header_map (modules_config.json)
import os

from openpyxl import Workbook
from openpyxl.formatting.rule import CellIsRule, FormulaRule
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

_script_dir = os.path.dirname(os.path.abspath(__file__))
_root_dir = os.path.normpath(os.path.join(_script_dir, '..', '..'))
output_dir = os.environ.get('AUDIT_TEMPLATES_DIR', os.path.join(_root_dir, 'Templates_Excel'))
os.makedirs(output_dir, exist_ok=True)
output_file = os.path.join(output_dir, "Template_Audit_M365.xlsx")

ENTETE_FONT = Font(bold=True, color="FFFFFF", name="Arial")
ENTETE_FILL = PatternFill("solid", fgColor="4F81BD")
ROUGE = dict(fill=PatternFill("solid", fgColor="FFC7CE"), font=Font(bold=True, color="9C0006"))
ORANGE = dict(fill=PatternFill("solid", fgColor="FFEB9C"), font=Font(bold=True, color="9C5700"))
VERT = dict(fill=PatternFill("solid", fgColor="C6EFCE"), font=Font(bold=True, color="006100"))
FIN = 20000

FEUILLES = {
    "Comptes": [("Prénom / Nom affiché", 22), ("Nom", 16), ("UPN", 34), ("Type", 9), ("Actif", 7), ("Création", 17),
                ("Licences", 30), ("Dernier changement MDP", 17), ("MDP > 6 mois", 9), ("Dernière connexion", 17),
                ("Jamais connecté", 9), ("Connexion > 6 mois", 9), ("MFA enregistrée", 10), ("Méthodes MFA", 28),
                ("Rôles admin", 28), ("Synchronisé AD", 10), ("MDP n'expire jamais", 10), ("Applications (licences)", 60)],
    "Rôles admin": [("Rôle", 30), ("Membre", 24), ("UPN", 34), ("Type", 12), ("Actif", 7), ("MFA", 7),
                    ("Méthodes MFA", 28), ("Synchronisé AD", 10), ("Dernière connexion", 17), ("Portée", 10)],
    "Invités": [("Nom", 24), ("UPN", 40), ("Mail", 28), ("Actif", 7), ("Créé le", 17), ("Invitation", 12),
                ("Dernière connexion", 17), ("Jamais connecté", 9), ("Licences", 24), ("Rôles admin", 24)],
    "Sécurité": [("Paramètre", 50), ("Valeur", 40), ("Statut", 11), ("Commentaire", 80)],
    "Appareils": [("Appareil", 22), ("OS", 12), ("Version", 14), ("Jonction", 20), ("Actif", 7),
                  ("Dernière connexion", 17), ("Conforme", 9), ("Géré (Intune)", 9), ("LAPS sauvegardé", 14),
                  ("LAPS dernière sauvegarde", 17), ("LAPS prochaine rotation", 17), ("Intune", 8),
                  ("Chiffré (BitLocker)", 10), ("Clé BitLocker Entra", 10), ("Conformité Intune", 13),
                  ("Dernière synchro Intune", 13)],
    "Accès conditionnel": [("Stratégie", 34), ("État", 13), ("Utilisateurs inclus", 30), ("Exclusions", 9),
                           ("Applications", 22), ("Conditions", 40), ("Contrôles", 30), ("Session", 20),
                           ("Couvre", 45), ("Alerte", 40)],
    "Intune": [("Stratégie", 34), ("Type", 30), ("Plateforme", 18), ("Attribuée", 9), ("Thèmes de sécurité", 45),
               ("Paramètres actifs", 9), ("Exemples de paramètres", 70), ("Modifiée le", 11)],
    "Référentiel sécurité": [("Domaine", 10), ("Contrôle", 45), ("Statut", 24), ("Détail", 80), ("Criticité", 9),
                             ("Recommandation", 80)],
}


def regle(ws, plage, valeur, style, egal=True):
    if egal:
        ws.conditional_formatting.add(plage, CellIsRule(operator="equal", formula=[f'"{valeur}"'], **style))
    else:
        ws.conditional_formatting.add(plage, FormulaRule(formula=[valeur], **style))


wb = Workbook()
wb.remove(wb.active)
for nom, colonnes in FEUILLES.items():
    ws = wb.create_sheet(nom)
    L = {}
    for i, (titre, largeur) in enumerate(colonnes, start=1):
        c = ws.cell(row=1, column=i, value=titre)
        c.font, c.fill = ENTETE_FONT, ENTETE_FILL
        c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        ws.column_dimensions[get_column_letter(i)].width = largeur
        L[titre] = get_column_letter(i)
    ws.freeze_panes = "B2"
    p = lambda t: f"{L[t]}2:{L[t]}{FIN}"
    if nom in ("Comptes", "Rôles admin"):
        col = "MFA enregistrée" if nom == "Comptes" else "MFA"
        regle(ws, p(col), "Non", ROUGE)
        regle(ws, p(col), "Oui", VERT)
        regle(ws, p("Synchronisé AD"), f'AND(${L["Synchronisé AD"]}2="Oui",${L["Rôles admin" if nom == "Comptes" else "Rôle"]}2<>"")', ORANGE, egal=False)
    if nom == "Comptes":
        for t in ("Jamais connecté", "Connexion > 6 mois", "MDP > 6 mois"):
            regle(ws, p(t), "True", ORANGE)
        regle(ws, p("Rôles admin"), f'LEN(${L["Rôles admin"]}2)>0', dict(font=Font(bold=True, color="9C0006")), egal=False)
    if nom == "Rôles admin":
        regle(ws, p("Rôle"), "Global Administrator", dict(font=Font(bold=True, color="9C0006")))
    if nom == "Invités":
        regle(ws, p("Invitation"), "En attente", ORANGE)
        regle(ws, p("Rôles admin"), f'LEN(${L["Rôles admin"]}2)>0', ROUGE, egal=False)
    if nom == "Sécurité":
        regle(ws, p("Statut"), "Critique", ROUGE)
        regle(ws, p("Statut"), "Attention", ORANGE)
        regle(ws, p("Statut"), "OK", VERT)
        for t in ("Valeur", "Commentaire"):
            for c in ws[L[t]]:
                c.alignment = Alignment(wrap_text=True, vertical="top")
    if nom == "Accès conditionnel":
        regle(ws, p("État"), "Mode rapport", ORANGE)
        regle(ws, p("État"), "Désactivée", dict(font=Font(color="7F7F7F")))
        regle(ws, p("Alerte"), f'LEN(${L["Alerte"]}2)>0', ORANGE, egal=False)
    if nom == "Intune":
        regle(ws, p("Attribuée"), "Non", ORANGE)
    if nom == "Référentiel sécurité":
        for v, st in (("En place", VERT), ("Partiel", ORANGE), ("Configuré mais non attribué", ORANGE), ("Absent", ROUGE)):
            regle(ws, p("Statut"), v, st)
    if nom == "Appareils":
        regle(ws, p("Chiffré (BitLocker)"), "Non", ROUGE)
        regle(ws, p("LAPS sauvegardé"), "Non", ROUGE)
        regle(ws, p("LAPS sauvegardé"), "Oui", VERT)
        regle(ws, p("Conforme"), "Non", ORANGE)

wl = wb.create_sheet("Legende")
for ligne in [
    ("Élément", "Signification"),
    ("Source", "Microsoft Graph en lecture seule (Audit_M365.py), connexion par code avec un compte admin du client"),
    ("Dernière connexion", "signInActivity : nécessite Entra ID P1 ; sinon « Non disponible (licence Entra ID P1 requise) »"),
    ("MFA enregistrée", "Rapport d'enregistrement des méthodes (P1) ; sans P1, méthodes lues compte par compte (500 comptes max)"),
    ("Rôles admin", "Rôles Entra ID actifs (attributions permanentes) ; un admin cloud ne devrait pas être synchronisé depuis l'AD"),
    ("Sécurité", "Paramètres du tenant : sécurité par défaut / accès conditionnel (MFA imposée), admins globaux, "
                 "consentement aux applications, invitations"),
    ("LAPS", "LAPS Entra ID : mot de passe administrateur local sauvegardé dans Entra ID (appareils joints). "
             "Appareils hybrides : voir aussi Audit_LAPS (AD)"),
]:
    wl.append(ligne)
for c in wl[1]:
    c.font, c.fill = ENTETE_FONT, ENTETE_FILL
wl.column_dimensions["A"].width = 22
wl.column_dimensions["B"].width = 120
wb.save(output_file)
print(f"Fichier genere : {output_file}")
