# 37_Audit_GPO_Securite.ps1
# Version      : 1.0
# Derniere modif : Creation - controle des GPO par rapport au referentiel de durcissement AD (gpo.md)
# Role         : Lit le CONTENU de toutes les GPO du domaine dans SYSVOL (les noms ne sont pas fiables) :
#                  Registry.pol (modeles d'administration, ordinateur et utilisateur), GptTmpl.inf (options de
#                  securite, services, Kerberos), audit.csv (strategie d'audit avancee), preferences Registre et
#                  Services, scripts de demarrage. Chaque mesure du referentiel est evaluee sur les GPO ACTIVES et
#                  LIEES : En place / Partiel / Non conforme / Configure mais non applique / Absent.
# Sorties      : AD\<HOTE>.<domaine>_Audit_GPO_Referentiel.csv   une ligne par mesure du referentiel
#                AD\<HOTE>.<domaine>_Audit_GPO_Parametres.csv     tous les parametres de securite trouves, par GPO
# Usage        : Lance via main.ps1 ou ansible/audit.yml (profil dc_principal). Necessite GPMC + RSAT AD.
#                Test hors domaine : $env:AUDIT_GPO_SIMULATION = dossier contenant gpos.json + Policies\{GUID}\...
# Limite       : pas de calcul de precedence ni de filtrage de securite / WMI : une mesure est "En place" si au
#                moins une GPO active et liee la configure correctement (les OU de liaison sont indiquees).
# ============================================================
$ErrorActionPreference = 'Continue'
$tempCsv = $env:AUDIT_TEMP_CSV
$Simu    = $env:AUDIT_GPO_SIMULATION

# --- Inventaire des GPO et de leurs liaisons ----------------
if ($Simu) {
    $DomainName = 'simulation.local'
    $Policies   = Join-Path $Simu 'Policies'
    $Gpos = Get-Content (Join-Path $Simu 'gpos.json') -Raw | ConvertFrom-Json
    $Liens = @{}
    foreach ($g in $Gpos) { $Liens[$g.Id.Trim('{}').ToLower()] = @($g.Links | ForEach-Object { [pscustomobject]@{ Cible = $_.Cible; Actif = [bool]$_.Actif } }) }
    $Postes = @(); $DcOs = @()
} else {
    Import-Module GroupPolicy -ErrorAction Stop
    Import-Module ActiveDirectory -ErrorAction Stop
    $Dom        = Get-ADDomain
    $DomainName = $Dom.DNSRoot
    $Policies   = "\\$DomainName\SYSVOL\$DomainName\Policies"
    $Gpos = Get-GPO -All | ForEach-Object { [pscustomobject]@{ Id = $_.Id.ToString(); DisplayName = $_.DisplayName; GpoStatus = "$($_.GpoStatus)" } }
    $Liens = @{}
    $porteurs = @(Get-ADObject -LDAPFilter '(gPLink=*)' -SearchBase $Dom.DistinguishedName -Properties gPLink, Name, objectClass)
    try { $porteurs += Get-ADObject -LDAPFilter '(&(objectClass=site)(gPLink=*))' -SearchBase "CN=Sites,$((Get-ADRootDSE).configurationNamingContext)" -Properties gPLink, Name, objectClass } catch {}
    foreach ($o in $porteurs) {
        $cible = if ($o.objectClass -eq 'domainDNS') { "Domaine" } elseif ($o.objectClass -eq 'site') { "Site:$($o.Name)" } else { $o.Name }
        foreach ($m in [regex]::Matches($o.gPLink, '\[LDAP://cn=(\{[0-9A-Fa-f-]+\}),[^;]*;(\d)\]')) {
            $id = $m.Groups[1].Value.Trim('{}').ToLower()
            if (-not $Liens[$id]) { $Liens[$id] = @() }
            $Liens[$id] += [pscustomobject]@{ Cible = $cible; Actif = (([int]$m.Groups[2].Value) -band 1) -eq 0 }
        }
    }
    $Postes = @(Get-ADComputer -Filter 'Enabled -eq $true' -Properties OperatingSystem, PrimaryGroupID)
    $DcOs = @(Get-ADDomainController -Filter * | ForEach-Object { $_.OperatingSystem })
}
$Hote = if ($Simu) { 'SIMU' } else { "$env:COMPUTERNAME.$DomainName" }
$Dossier = if ($Simu) { $Simu } else { Join-Path $tempCsv 'AD' }
$null = New-Item -ItemType Directory -Force -Path $Dossier
Write-Host "$(@($Gpos).Count) GPO(s), lecture du contenu dans $Policies"

# --- Lecteurs de fichiers GPO -------------------------------
function Normalise-Cle([string]$k) {
    $k = $k.Trim().ToLower() -replace '^(machine|user|hkey_local_machine|hkey_current_user|hklm|hkcu)\\', ''
    return $k.TrimEnd('\')
}

function Lire-RegistryPol([string]$Chemin) {
    # Format PReg : 'PReg' + version, puis [cle;valeur;type;taille;donnees] en UTF-16LE
    $b = [IO.File]::ReadAllBytes($Chemin)
    $res = New-Object System.Collections.Generic.List[object]
    if ($b.Length -lt 8) { return $res }
    $i = 8
    $lireChaine = {
        $d = $script:i
        while ($script:i -lt $b.Length - 1 -and -not ($b[$script:i] -eq 0 -and $b[$script:i + 1] -eq 0)) { $script:i += 2 }
        $s = [Text.Encoding]::Unicode.GetString($b, $d, $script:i - $d)
        $script:i += 2
        $s
    }
    $script:i = $i
    while ($script:i -lt $b.Length - 1) {
        if (-not ($b[$script:i] -eq 0x5B -and $b[$script:i + 1] -eq 0)) { $script:i += 2; continue }
        $script:i += 2
        $cle = & $lireChaine; $script:i += 2
        $nom = & $lireChaine; $script:i += 2
        if ($script:i + 10 -gt $b.Length) { break }
        $type = [BitConverter]::ToUInt32($b, $script:i); $script:i += 6
        $taille = [BitConverter]::ToUInt32($b, $script:i); $script:i += 6
        $val = $null
        if ($taille -gt 0 -and $script:i + $taille -le $b.Length) {
            switch ($type) {
                4       { $val = [BitConverter]::ToUInt32($b, $script:i) }
                11      { $val = [BitConverter]::ToUInt64($b, $script:i) }
                { $_ -in 1, 2 } { $val = [Text.Encoding]::Unicode.GetString($b, $script:i, $taille).TrimEnd([char]0) }
                7       { $val = ([Text.Encoding]::Unicode.GetString($b, $script:i, $taille).Split([char]0) | Where-Object { $_ }) -join '|' }
                default { $val = ($b[$script:i..($script:i + $taille - 1)] | ForEach-Object { $_.ToString('X2') }) -join '' }
            }
        }
        $script:i += $taille + 2
        if ($nom -like '`*`*del*' -or $nom -like '`*`*Del*' -or $nom -like '`*`*SecureKey*') { continue }
        $res.Add([pscustomobject]@{ Cle = (Normalise-Cle $cle); Nom = $nom.ToLower(); Valeur = $val })
    }
    return $res
}

function Lire-GptTmpl([string]$Chemin) {
    $res = New-Object System.Collections.Generic.List[object]
    $section = ''
    foreach ($l in Get-Content -LiteralPath $Chemin) {
        $l = $l.Trim()
        if ($l -match '^\[(.+)\]$') { $section = $Matches[1]; continue }
        if (-not $l -or $l.StartsWith(';')) { continue }
        switch ($section) {
            'Registry Values' {
                if ($l -match '^(.+)\\([^\\=]+)=(\d+),(.*)$') {
                    $cle, $nom, $type, $v = $Matches[1], $Matches[2], $Matches[3], $Matches[4].Trim('"')
                    if ($type -eq '4' -and $v -match '^-?\d+$') { $v = [int64]$v }
                    $res.Add([pscustomobject]@{ Cle = (Normalise-Cle $cle); Nom = $nom.ToLower(); Valeur = $v })
                }
            }
            'Service General Setting' {
                if ($l -match '^"?([^",]+)"?\s*,\s*(\d)') {
                    $res.Add([pscustomobject]@{ Cle = 'services'; Nom = $Matches[1].ToLower(); Valeur = [int]$Matches[2] })
                }
            }
            { $_ -in 'System Access', 'Kerberos Policy' } {
                if ($l -match '^([^=]+?)\s*=\s*(.*)$') {
                    $res.Add([pscustomobject]@{ Cle = $section.ToLower(); Nom = $Matches[1].ToLower(); Valeur = $Matches[2].Trim('"') })
                }
            }
        }
    }
    return $res
}

function Lire-AuditCsv([string]$Chemin) {
    $res = New-Object System.Collections.Generic.List[object]
    foreach ($r in (Import-Csv -LiteralPath $Chemin)) {
        $guid = "$($r.'Subcategory GUID')".Trim('{}').ToLower()
        if ($guid -and "$($r.'Setting Value')" -match '^\d+$') {
            $res.Add([pscustomobject]@{ Cle = 'auditpol'; Nom = $guid; Valeur = [int]$r.'Setting Value'; Libelle = $r.Subcategory })
        }
    }
    return $res
}

function Lire-PrefRegistre([string]$Chemin) {
    $res = New-Object System.Collections.Generic.List[object]
    [xml]$x = Get-Content -LiteralPath $Chemin -Raw
    foreach ($p in $x.SelectNodes('//Properties')) {
        if ($p.action -eq 'D') { continue }
        $v = $p.value
        if ($p.type -eq 'REG_DWORD' -and $v -match '^[0-9A-Fa-f]+$') { $v = [Convert]::ToInt64($v, 16) }
        $res.Add([pscustomobject]@{ Cle = (Normalise-Cle "$($p.hive)\$($p.key)"); Nom = "$($p.name)".ToLower(); Valeur = $v })
    }
    return $res
}

function Lire-PrefServices([string]$Chemin) {
    $res = New-Object System.Collections.Generic.List[object]
    [xml]$x = Get-Content -LiteralPath $Chemin -Raw
    foreach ($p in $x.SelectNodes('//Properties')) {
        $start = switch -Regex ("$($p.startupType)") { 'DISABLED' { 4 } 'MANUAL' { 3 } 'AUTOMATIC' { 2 } default { $null } }
        if ($p.serviceName -and $null -ne $start) { $res.Add([pscustomobject]@{ Cle = 'services'; Nom = "$($p.serviceName)".ToLower(); Valeur = $start }) }
    }
    return $res
}

function Lire-Scripts([string]$Dossier) {
    $res = New-Object System.Collections.Generic.List[object]
    foreach ($f in 'scripts.ini', 'psscripts.ini') {
        $p = Join-Path $Dossier $f
        if (Test-Path -LiteralPath $p) {
            foreach ($l in Get-Content -LiteralPath $p) {
                if ($l -match '^\d+CmdLine=(.+)$') { $res.Add([pscustomobject]@{ Cle = 'scripts'; Nom = (Split-Path $Matches[1] -Leaf).ToLower(); Valeur = $Matches[1] }) }
            }
        }
    }
    return $res
}

# --- Collecte : tous les parametres de toutes les GPO -------
$Params = New-Object System.Collections.Generic.List[object]
foreach ($g in $Gpos) {
    $id = $g.Id.Trim('{}').ToLower()
    $racine = Join-Path $Policies "{$($g.Id.Trim('{}'))}"
    if (-not (Test-Path -LiteralPath $racine)) { Write-Warning "Dossier SYSVOL absent : $($g.DisplayName)"; continue }
    $lnk = @($Liens[$id])
    $actifs = @($lnk | Where-Object { $_.Actif })
    $statut = "$($g.GpoStatus)"
    foreach ($portee in 'M', 'U') {
        $sous = if ($portee -eq 'M') { 'Machine' } else { 'User' }
        $desactive = $statut -eq 'AllSettingsDisabled' -or ($portee -eq 'M' -and $statut -eq 'ComputerSettingsDisabled') -or
                     ($portee -eq 'U' -and $statut -eq 'UserSettingsDisabled')
        $sources = @(
            @{ F = "$sous\Registry.pol"; S = 'Modele d''administration'; L = { param($p) Lire-RegistryPol $p } },
            @{ F = "$sous\Microsoft\Windows NT\SecEdit\GptTmpl.inf"; S = 'Options de securite'; L = { param($p) Lire-GptTmpl $p } },
            @{ F = "$sous\Microsoft\Windows NT\Audit\audit.csv"; S = 'Audit avance'; L = { param($p) Lire-AuditCsv $p } },
            @{ F = "$sous\Preferences\Registry\Registry.xml"; S = 'Preference Registre'; L = { param($p) Lire-PrefRegistre $p } },
            @{ F = "$sous\Preferences\Services\Services.xml"; S = 'Preference Services'; L = { param($p) Lire-PrefServices $p } })
        foreach ($s in $sources) {
            $p = Join-Path $racine $s.F
            if (-not (Test-Path -LiteralPath $p)) { continue }
            try { $lus = & $s.L $p } catch { Write-Warning "Lecture impossible : $p ($_)"; continue }
            foreach ($x in $lus) {
                $Params.Add([pscustomobject]@{ GpoId = $id; Gpo = $g.DisplayName; Portee = $portee; Source = $s.S
                    Cle = $x.Cle; Nom = $x.Nom; Valeur = $x.Valeur; Applique = (-not $desactive -and $actifs.Count -gt 0)
                    Liens = ($lnk | ForEach-Object { if ($_.Actif) { $_.Cible } else { "$($_.Cible) (lien desactive)" } }) -join ', '
                    Etat = $statut })
            }
        }
        foreach ($x in (Lire-Scripts (Join-Path $racine "$sous\Scripts"))) {
            $Params.Add([pscustomobject]@{ GpoId = $id; Gpo = $g.DisplayName; Portee = $portee; Source = 'Script'; Cle = $x.Cle
                Nom = $x.Nom; Valeur = $x.Valeur; Applique = (-not $desactive -and $actifs.Count -gt 0)
                Liens = ($lnk | ForEach-Object { $_.Cible }) -join ', '; Etat = $statut })
        }
    }
}
Write-Host "$($Params.Count) parametre(s) lu(s)"

# --- Referentiel (gpo.md) : chaque mesure = regles sur le CONTENU des GPO ---
# R : K = cle (sans ruche), N = nom de valeur (ou 'auditpol' + GUID, 'services' + service), T = test, A = attendu
function Regle($K, $N, $T, $A, $P = 'M') { @{ K = $K.ToLower(); N = $N.ToLower(); T = $T; A = $A; P = $P } }
$LSA   = 'system\currentcontrolset\control\lsa'
$MSV   = 'system\currentcontrolset\control\lsa\msv1_0'
$NETL  = 'system\currentcontrolset\services\netlogon\parameters'
$POLS  = 'software\microsoft\windows\currentversion\policies\system'
$TS    = 'software\policies\microsoft\windows nt\terminal services'
$SCH   = 'system\currentcontrolset\control\securityproviders\schannel\protocols'
$AUD   = { param($req) { param($v) ([int]$v -band $req) -eq $req }.GetNewClosure() }
$Egal  = { param($x) { param($v) "$v" -eq "$x" }.GetNewClosure() }

$Ref = @(
  @{ M = 'Applocker-Enabled'; C = 'Execution de code'; N = 'Common'; Cr = 2; Mode = 'any'
     R = @(Regle 'software\policies\microsoft\windows\srpv2\exe' 'enforcementmode' { param($v) "$v" -eq '1' } 'Regles AppLocker Exe en mode applique')
     Reco = 'Deployer AppLocker (ou WDAC) en mode audit puis applique sur postes et serveurs.' }
  @{ M = 'ASR-Exploit-Guard'; C = 'Execution de code'; N = 'Common'; Cr = 2; Special = 'ASR'
     Reco = 'Activer les regles ASR de Defender en mode blocage (19 regles), apres une phase en mode audit.' }
  @{ M = 'Bitlocker-Enabled'; C = 'Protection des postes'; N = 'Common'; Cr = 3
     R = @((Regle 'software\policies\microsoft\fve' 'osactivedirectorybackup' (& $Egal 1) 'Sauvegarde des cles dans l''AD'),
           (Regle 'software\policies\microsoft\fve' 'encryptionmethodwithxtsos' { param($v) "$v" -in '6', '7' } 'XTS-AES 128/256'),
           (Regle 'software\policies\microsoft\fve' 'usetpm' { param($v) "$v" -in '1', '2' } 'TPM requis ou autorise'))
     Reco = 'Configurer BitLocker (XTS-AES 256, TPM, cles de recuperation sauvegardees dans l''AD) et chiffrer les postes.' }
  @{ M = 'Bloodhound-Mitigation'; C = 'Reconnaissance'; N = 'Common'; Cr = 1
     R = @(Regle 'system\currentcontrolset\services\lanmanserver\defaultsecurity' 'srvsvcsessioninfo' { param($v) "$v".Length -gt 0 } 'ACL restreinte (NetSessionEnum)')
     Reco = 'Restreindre l''enumeration des sessions (SrvsvcSessionInfo) pour gener la reconnaissance (BloodHound).' }
  @{ M = 'IPv6-Disabled'; C = 'Empoisonnement reseau'; N = 'Common'; Cr = 1
     R = @(Regle 'system\currentcontrolset\services\tcpip6\parameters' 'disabledcomponents' { param($v) [int64]$v -band 0x20 -or [int64]$v -eq 255 } '0xFF (ou IPv4 prefere)')
     Reco = 'Desactiver IPv6 la ou il n''est pas utilise (attaques mitm6 / DHCPv6), ou a defaut proteger contre les annonces RA.' }
  @{ M = 'Kerberos-AES-Enabled'; C = 'Authentification'; N = 'Common'; Cr = 2
     R = @(Regle "$POLS\kerberos\parameters" 'supportedencryptiontypes' { param($v) $x = [int64]$v; ($x -band 0x18) -and -not ($x -band 0x7) } 'AES uniquement (pas de RC4 / DES)')
     Reco = 'Limiter Kerberos a AES128/AES256 (desactiver RC4 et DES) apres verification des comptes de service.' }
  @{ M = 'Kerberos-Armoring-Enabled'; C = 'Authentification'; N = 'Common'; Cr = 1
     R = @((Regle "$POLS\kdc\parameters" 'enablecbacandarmor' (& $Egal 1) 'KDC : blindage Kerberos'),
           (Regle "$POLS\kerberos\parameters" 'enablecbacandarmor' (& $Egal 1) 'Clients : blindage Kerberos'))
     Reco = 'Activer le blindage Kerberos (FAST) cote KDC et clients.' }
  @{ M = 'LAPS-Enabled'; C = 'Protection des postes'; N = 'Common'; Cr = 3; Mode = 'any'
     R = @((Regle 'software\microsoft\policies\laps' 'backupdirectory' { param($v) "$v" -in '1', '2' } 'Windows LAPS : sauvegarde AD ou Entra'),
           (Regle 'software\policies\microsoft services\admpwd' 'admpwdenabled' (& $Egal 1) 'LAPS historique active'))
     Reco = 'Deployer Windows LAPS par GPO (sauvegarde AD chiffree, 14 caracteres minimum, rotation reguliere).' }
  @{ M = 'LDAP-CBT-Enabled'; C = 'Relais NTLM'; N = 'Common'; Cr = 2
     R = @(Regle 'system\currentcontrolset\services\ntds\parameters' 'ldapenforcechannelbinding' (& $Egal 2) 'Toujours (2)')
     Reco = 'Exiger le Channel Binding LDAP sur les DC (apres audit des evenements 3039).' }
  @{ M = 'LDAP-Client-Signing-Required'; C = 'Relais NTLM'; N = 'Common'; Cr = 2
     R = @(Regle 'system\currentcontrolset\services\ldap' 'ldapclientintegrity' (& $Egal 2) 'Exiger la signature (2)')
     Reco = 'Exiger la signature LDAP cote client.' }
  @{ M = 'LDAP-Server-Signing-Required'; C = 'Relais NTLM'; N = 'Common'; Cr = 3
     R = @(Regle 'system\currentcontrolset\services\ntds\parameters' 'ldapserverintegrity' (& $Egal 2) 'Exiger la signature (2)')
     Reco = 'Exiger la signature LDAP sur les controleurs de domaine (apres audit des evenements 2889).' }
  @{ M = 'LMHASH-Disabled'; C = 'Authentification'; N = 'Level2016'; Cr = 2; Defaut = 'NoLMHash = 1 par defaut depuis Windows Vista / 2008'
     R = @(Regle $LSA 'nolmhash' (& $Egal 1) 'NoLMHash = 1')
     Reco = 'Interdire le stockage des empreintes LM.' }
  @{ M = 'LLMNR-Disabled'; C = 'Empoisonnement reseau'; N = 'Common'; Cr = 3
     R = @(Regle 'software\policies\microsoft\windows nt\dnsclient' 'enablemulticast' (& $Egal 0) 'Desactive (0)')
     Reco = 'Desactiver LLMNR (empoisonnement Responder et vol d''empreintes NTLM).' }
  @{ M = 'Logs-Advanced (journalisation avancee)'; C = 'Journalisation'; N = 'Common'; Cr = 2
     R = @((Regle 'auditpol' '0cce9215-69ae-11d9-bed3-505054503030' (& $AUD 3) 'Ouverture de session : succes + echec'),
           (Regle 'auditpol' '0cce922b-69ae-11d9-bed3-505054503030' (& $AUD 1) 'Creation de processus : succes'),
           (Regle 'auditpol' '0cce923f-69ae-11d9-bed3-505054503030' (& $AUD 3) 'Validation des identifiants : succes + echec'),
           (Regle 'auditpol' '0cce9235-69ae-11d9-bed3-505054503030' (& $AUD 3) 'Gestion des comptes : succes + echec'),
           (Regle 'auditpol' '0cce9237-69ae-11d9-bed3-505054503030' (& $AUD 1) 'Gestion des groupes de securite : succes'),
           (Regle 'auditpol' '0cce9242-69ae-11d9-bed3-505054503030' (& $AUD 3) 'Service d''authentification Kerberos : succes + echec'),
           (Regle 'auditpol' '0cce923c-69ae-11d9-bed3-505054503030' (& $AUD 1) 'Modifications du service d''annuaire : succes'),
           (Regle 'auditpol' '0cce9217-69ae-11d9-bed3-505054503030' (& $AUD 2) 'Verrouillage de compte : echec'),
           (Regle 'auditpol' '0cce922f-69ae-11d9-bed3-505054503030' (& $AUD 1) 'Modification de la strategie d''audit : succes'),
           (Regle 'auditpol' '0cce9228-69ae-11d9-bed3-505054503030' (& $AUD 1) 'Utilisation de privileges sensibles : succes'),
           (Regle 'auditpol' '0cce9224-69ae-11d9-bed3-505054503030' (& $AUD 3) 'Partage de fichiers : succes + echec'),
           (Regle 'auditpol' '0cce9245-69ae-11d9-bed3-505054503030' (& $AUD 3) 'Stockage amovible : succes + echec'))
     Reco = 'Configurer la strategie d''audit avancee (serveurs et postes) et centraliser les journaux.' }
  @{ M = 'mDNS-Disabled'; C = 'Empoisonnement reseau'; N = 'Common'; Cr = 2
     R = @(Regle 'system\currentcontrolset\services\dnscache\parameters' 'enablemdns' (& $Egal 0) 'EnableMDNS = 0')
     Reco = 'Desactiver mDNS (resolution de noms multicast exploitable comme LLMNR).' }
  @{ M = 'MSCache-Disabled'; C = 'Identifiants'; N = 'Common'; Cr = 2
     R = @(Regle 'software\microsoft\windows nt\currentversion\winlogon' 'cachedlogonscount' { param($v) [int]("$v" -replace '\D', '') -le 2 } '1 (2 maximum)')
     Reco = 'Limiter le cache des identifiants (CachedLogonsCount <= 2, 1 recommande).' }
  @{ M = 'NBT-NS-Disabled'; C = 'Empoisonnement reseau'; N = 'Common'; Cr = 3; Mode = 'any'
     R = @((Regle 'software\policies\microsoft\windows nt\dnsclient' 'enablenetbios' (& $Egal 0) 'Parametres NetBIOS : desactive (Windows 11 / 2025)'),
           (Regle 'system\currentcontrolset\services\netbt\parameters' 'nodetype' (& $Egal 2) 'NodeType = 2 (P-node)'),
           (Regle 'scripts' '*' { param($v) "$v" -match 'nbt|netbios' } 'Script de desactivation NetBIOS'))
     Reco = 'Desactiver NetBIOS (NBT-NS) : script de demarrage / DHCP (2016) ou parametre NetBIOS (Windows 11 / 2025).' }
  @{ M = 'NTLM1-LM-Disabled'; C = 'Authentification'; N = 'Common'; Cr = 3
     R = @((Regle $LSA 'lmcompatibilitylevel' (& $Egal 5) 'NTLMv2 uniquement, refuser LM et NTLM (5)'),
           (Regle $MSV 'allownullsessionfallback' (& $Egal 0) 'Pas de session nulle'))
     Reco = 'Niveau d''authentification LAN Manager = 5 (NTLMv2 uniquement, refuser LM et NTLMv1).' }
  @{ M = 'NTLM-Audit-Enabled'; C = 'Authentification'; N = 'Common'; Cr = 1
     R = @((Regle $MSV 'auditreceivingntlmtraffic' (& $Egal 2) 'Auditer le trafic NTLM entrant'),
           (Regle $NETL 'auditntlmindomain' (& $Egal 7) 'Auditer NTLM dans le domaine'))
     Reco = 'Activer l''audit NTLM pour identifier les usages avant restriction.' }
  @{ M = 'NTLM-Disabled'; C = 'Authentification'; N = 'Common'; Cr = 1
     R = @(Regle $NETL 'restrictntlmindomain' (& $Egal 7) 'Refuser tout NTLM dans le domaine')
     Reco = 'Objectif a terme : refuser NTLM dans le domaine (apres la phase d''audit NTLM).' }
  @{ M = 'NTLMv2-128bits-Required'; C = 'Authentification'; N = 'Common'; Cr = 1
     R = @((Regle $MSV 'ntlmminclientsec' (& $Egal 537395200) 'NTLMv2 + 128 bits (clients)'),
           (Regle $MSV 'ntlmminserversec' (& $Egal 537395200) 'NTLMv2 + 128 bits (serveurs)'))
     Reco = 'Exiger la securite de session NTLMv2 et le chiffrement 128 bits.' }
  @{ M = 'Powershell-Hardened'; C = 'Journalisation'; N = 'Common'; Cr = 2
     R = @((Regle 'software\policies\microsoft\windows\powershell\scriptblocklogging' 'enablescriptblocklogging' (& $Egal 1) 'Journalisation des blocs de script'),
           (Regle 'software\policies\microsoft\windows\powershell\modulelogging' 'enablemodulelogging' (& $Egal 1) 'Journalisation des modules'),
           (Regle 'software\policies\microsoft\windows\powershell\transcription' 'enabletranscripting' (& $Egal 1) 'Transcription'))
     Reco = 'Activer la journalisation PowerShell (blocs de script, modules, transcription).' }
  @{ M = 'Proxy-Change-Disabled'; C = 'Empoisonnement reseau'; N = 'Common'; Cr = 1
     R = @(Regle 'software\policies\microsoft\internet explorer\control panel' 'proxy' (& $Egal 1) 'Modification du proxy interdite' 'U')
     Reco = 'Empecher les utilisateurs de modifier le proxy.' }
  @{ M = 'RDP-hijacking-Mitigation'; C = 'Acces distant'; N = 'Common'; Cr = 1
     R = @((Regle $TS 'disablepasswordsaving' (& $Egal 1) 'Pas d''enregistrement du mot de passe'),
           (Regle $TS 'maxdisconnectiontime' { param($v) [int64]$v -gt 0 -and [int64]$v -le 3600000 } 'Sessions deconnectees fermees'))
     Reco = 'Fermer les sessions RDP deconnectees et interdire l''enregistrement des mots de passe.' }
  @{ M = 'RDP-NLA-Enabled'; C = 'Acces distant'; N = 'Common'; Cr = 2; Defaut = 'NLA active par defaut depuis Windows 2012'
     R = @(Regle $TS 'userauthentication' (& $Egal 1) 'NLA exigee')
     Reco = 'Exiger l''authentification au niveau du reseau (NLA) pour le Bureau a distance.' }
  @{ M = 'RPC-Hardened'; C = 'Acces distant'; N = 'Common'; Cr = 1
     R = @((Regle 'software\policies\microsoft\windows nt\rpc' 'enableauthepresolution' (& $Egal 1) 'Authentification du mappeur de points de terminaison'),
           (Regle 'software\policies\microsoft\windows nt\rpc' 'restrictremoteclients' (& $Egal 1) 'Clients RPC authentifies'))
     Reco = 'Exiger l''authentification des clients RPC.' }
  @{ M = 'ScreenLock-enabled'; C = 'Protection des postes'; N = 'Common'; Cr = 2; Mode = 'any'
     R = @((Regle $POLS 'inactivitytimeoutsecs' { param($v) [int64]$v -gt 0 -and [int64]$v -le 900 } 'Limite d''inactivite <= 15 min'),
           (Regle 'software\policies\microsoft\windows\control panel\desktop' 'screensaverissecure' (& $Egal 1) 'Ecran de veille protege' 'U'))
     Reco = 'Verrouiller automatiquement les sessions apres 10 minutes d''inactivite.' }
  @{ M = 'Secure-NetLogon'; C = 'Relais NTLM'; N = 'Common'; Cr = 2; Defaut = 'Signature / scellement actives par defaut'
     R = @((Regle $NETL 'requiresignorseal' (& $Egal 1) 'RequireSignOrSeal = 1'), (Regle $NETL 'sealsecurechannel' (& $Egal 1) 'SealSecureChannel = 1'),
           (Regle $NETL 'requirestrongkey' (& $Egal 1) 'RequireStrongKey = 1'))
     Reco = 'Exiger signature, scellement et cle forte pour le canal securise Netlogon.' }
  @{ M = 'SMB-Client-Encrypt-Required'; C = 'Relais NTLM'; N = 'Level2025'; Cr = 1
     R = @(Regle 'software\policies\microsoft\windows\lanmanworkstation' 'requireencryption' (& $Egal 1) 'Chiffrement SMB exige')
     Reco = 'Windows 11 / Server 2025 : exiger le chiffrement SMB cote client.' }
  @{ M = 'SMB-Client-Signing-Enabled'; C = 'Relais NTLM'; N = 'Common'; Cr = 2; Defaut = 'Signature SMB exigee par defaut sur Windows 11 24H2 / Server 2025'
     R = @((Regle 'system\currentcontrolset\services\lanmanworkstation\parameters' 'requiresecuritysignature' (& $Egal 1) 'Signature toujours exigee'),
           (Regle 'system\currentcontrolset\services\lanmanworkstation\parameters' 'enableplaintextpassword' (& $Egal 0) 'Pas de mot de passe en clair'))
     Reco = 'Exiger la signature SMB cote client.' }
  @{ M = 'SMB-NTLM-Disabled'; C = 'Relais NTLM'; N = 'Level2025'; Cr = 1
     R = @(Regle 'software\policies\microsoft\windows\lanmanworkstation' 'blockntlm' (& $Egal 1) 'Bloquer NTLM pour SMB')
     Reco = 'Windows 11 / Server 2025 : bloquer NTLM pour les connexions SMB sortantes.' }
  @{ M = 'SMB-Server-Signing-Enabled'; C = 'Relais NTLM'; N = 'Common'; Cr = 3
     R = @(Regle 'system\currentcontrolset\services\lanmanserver\parameters' 'requiresecuritysignature' (& $Egal 1) 'Signature toujours exigee')
     Reco = 'Exiger la signature SMB sur tous les serveurs (protection contre le relais NTLM).' }
  @{ M = 'SMBv1-Disabled'; C = 'Relais NTLM'; N = 'Common'; Cr = 2; Mode = 'any'; Defaut = 'SMBv1 absent par defaut depuis Windows 10 1709 / Server 2019'
     R = @((Regle 'system\currentcontrolset\services\lanmanserver\parameters' 'smb1' (& $Egal 0) 'Serveur SMB1 = 0'),
           (Regle 'system\currentcontrolset\services\mrxsmb10' 'start' (& $Egal 4) 'Pilote client SMBv1 desactive'))
     Reco = 'Desactiver SMBv1 (EternalBlue / WannaCry).' }
  @{ M = 'SSDP-Disabled'; C = 'Empoisonnement reseau'; N = 'Common'; Cr = 1
     R = @(Regle 'services' 'ssdpsrv' (& $Egal 4) 'Service SSDPSRV desactive')
     Reco = 'Desactiver le service SSDP (UPnP).' }
  @{ M = 'TLS-Hardened'; C = 'Chiffrement'; N = 'Common'; Cr = 2
     R = @((Regle "$SCH\tls 1.0\server" 'enabled' (& $Egal 0) 'TLS 1.0 serveur desactive'), (Regle "$SCH\tls 1.1\server" 'enabled' (& $Egal 0) 'TLS 1.1 serveur desactive'),
           (Regle "$SCH\ssl 3.0\server" 'enabled' (& $Egal 0) 'SSL 3.0 serveur desactive'))
     Reco = 'Desactiver SSL 3.0, TLS 1.0 et TLS 1.1 (client et serveur).' }
  @{ M = 'UAC-Hardened'; C = 'Protection des postes'; N = 'Common'; Cr = 2; Defaut = 'UAC actif par defaut (EnableLUA = 1)'
     R = @((Regle $POLS 'enablelua' (& $Egal 1) 'UAC active'), (Regle $POLS 'consentpromptbehavioradmin' { param($v) "$v" -in '1', '2' } 'Demande d''identifiants / consentement sur bureau securise'),
           (Regle $POLS 'promptonsecuredesktop' (& $Egal 1) 'Bureau securise'), (Regle $POLS 'filteradministratortoken' (& $Egal 1) 'Compte Administrateur integre filtre'))
     Reco = 'Durcir le controle de compte d''utilisateur (UAC).' }
  @{ M = 'UNC-Paths-Hardened'; C = 'Relais NTLM'; N = 'Common'; Cr = 2; Defaut = 'Chemins SYSVOL / NETLOGON durcis par defaut depuis le correctif MS15-011'
     R = @((Regle 'software\policies\microsoft\windows\networkprovider\hardenedpaths' '\\*\sysvol' { param($v) "$v" -match 'requiremutualauthentication=1' -and "$v" -match 'requireintegrity=1' } '\\*\SYSVOL'),
           (Regle 'software\policies\microsoft\windows\networkprovider\hardenedpaths' '\\*\netlogon' { param($v) "$v" -match 'requiremutualauthentication=1' -and "$v" -match 'requireintegrity=1' } '\\*\NETLOGON'))
     Reco = 'Durcir les chemins UNC \\*\SYSVOL et \\*\NETLOGON (authentification mutuelle + integrite).' }
  @{ M = 'Wdigest-Disabled'; C = 'Identifiants'; N = 'Common'; Cr = 3; Defaut = 'WDigest desactive par defaut depuis Windows 8.1 / 2012 R2'
     R = @(Regle 'system\currentcontrolset\control\securityproviders\wdigest' 'uselogoncredential' (& $Egal 0) 'UseLogonCredential = 0')
     Reco = 'Desactiver WDigest (mots de passe en clair dans LSASS).' }
  @{ M = 'WebProxyAutoDiscovery-Disabled'; C = 'Empoisonnement reseau'; N = 'Common'; Cr = 1
     R = @(Regle 'services' 'winhttpautoproxysvc' (& $Egal 4) 'Service WinHttpAutoProxySvc desactive')
     Reco = 'Desactiver la decouverte automatique du proxy (WPAD).' }
  @{ M = 'WPAD-Computer-Disabled'; C = 'Empoisonnement reseau'; N = 'Common'; Cr = 2
     R = @(Regle 'software\microsoft\windows\currentversion\internet settings\winhttp' 'disablewpad' (& $Egal 1) 'DisableWpad = 1')
     Reco = 'Desactiver WPAD cote ordinateur.' }
  @{ M = 'WPAD-User-Disabled'; C = 'Empoisonnement reseau'; N = 'Common'; Cr = 1
     R = @(Regle 'software\microsoft\windows\currentversion\internet settings' 'autodetect' (& $Egal 0) 'AutoDetect = 0' 'U')
     Reco = 'Desactiver la detection automatique du proxy cote utilisateur.' }
  @{ M = 'WScript-Disabled'; C = 'Execution de code'; N = 'Common'; Cr = 2
     R = @(Regle 'software\microsoft\windows script host\settings' 'enabled' (& $Egal 0) 'Windows Script Host desactive')
     Reco = 'Desactiver Windows Script Host (vecteur courant de pieces jointes malveillantes).' }
  # --- Complements Netoptima (hors liste de reference) ---
  @{ M = 'Autorun-Disabled'; C = 'Protection des postes'; N = 'Complement'; Cr = 2; Mode = 'any'
     R = @((Regle 'software\microsoft\windows\currentversion\policies\explorer' 'nodrivetypeautorun' (& $Egal 255) 'Lecture automatique desactivee (tous lecteurs)'),
           (Regle 'software\microsoft\windows\currentversion\policies\explorer' 'noautorun' (& $Egal 1) 'Autorun desactive'))
     Reco = 'Desactiver l''execution automatique (AutoRun / AutoPlay) sur tous les lecteurs.' }
  @{ M = 'LSA-Protection (RunAsPPL)'; C = 'Identifiants'; N = 'Complement'; Cr = 2; Mode = 'any'
     R = @((Regle $LSA 'runasppl' { param($v) "$v" -in '1', '2' } 'LSASS processus protege'),
           (Regle 'software\policies\microsoft\windows\system' 'runasppl' { param($v) "$v" -in '1', '2' } 'LSASS processus protege (ADMX)'))
     Reco = 'Executer LSASS en processus protege (vol d''identifiants type Mimikatz).' }
  @{ M = 'Spooler-Disabled (DC)'; C = 'Relais NTLM'; N = 'Complement'; Cr = 2
     R = @(Regle 'services' 'spooler' (& $Egal 4) 'Service Spouleur desactive (GPO liee aux DC)')
     Reco = 'Desactiver le spouleur d''impression sur les controleurs de domaine (PrinterBug / PrintNightmare).' }
)

# --- Evaluation ---------------------------------------------
function Cherche($r) {
    @($Params | Where-Object { $_.Portee -eq $r.P -and $_.Cle -eq $r.K -and ($r.N -eq '*' -or $_.Nom -eq $r.N) })
}
$Lignes = foreach ($m in $Ref) {
    $ok = @(); $ko = @(); $abs = @(); $nonApp = @(); $gposM = @(); $valeurs = @(); $liaisons = @()
    if ($m.Special -eq 'ASR') {
        $asr = @($Params | Where-Object { $_.Cle -eq 'software\policies\microsoft\windows defender\windows defender exploit guard\asr\rules' })
        $app = @($asr | Where-Object Applique)
        $bloc = @($app | Where-Object { "$($_.Valeur)" -eq '1' } | Select-Object -ExpandProperty Nom -Unique)
        $audit = @($app | Where-Object { "$($_.Valeur)" -in '2', '6' } | Select-Object -ExpandProperty Nom -Unique)
        $st = if ($bloc.Count -ge 15) { 'En place' } elseif ($bloc.Count -gt 0 -or $audit.Count) { 'Partiel' } elseif ($asr) { 'Configure mais non applique' } else { 'Absent' }
        $gposM = @($asr | Select-Object -ExpandProperty Gpo -Unique); $liaisons = @($app | Select-Object -ExpandProperty Liens -Unique)
        $valeurs = @("$($bloc.Count) regle(s) en blocage, $($audit.Count) en audit")
        $attendu = '19 regles ASR en blocage'
    } else {
        foreach ($r in $m.R) {
            $t = Cherche $r
            $a = @($t | Where-Object Applique)
            if (-not $t) { $abs += $r.A; continue }
            if (-not $a) { $nonApp += $r.A; $gposM += $t.Gpo; continue }
            $bons = @($a | Where-Object { & $r.T $_.Valeur })
            $gposM += $a.Gpo; $liaisons += $a.Liens
            $valeurs += ($a | ForEach-Object { "$($r.A) : $($_.Valeur)" })
            if ($bons.Count -eq $a.Count) { $ok += $r.A }
            elseif ($bons) { $ko += "$($r.A) (valeurs contradictoires)" }
            else { $ko += $r.A }
        }
        $n = @($m.R).Count
        $st = if ($m.Mode -eq 'any') {
                  if ($ok) { 'En place' } elseif ($ko) { 'Non conforme' } elseif ($nonApp) { 'Configure mais non applique' } else { 'Absent' }
              } elseif ($ok.Count -eq $n) { 'En place' }
              elseif ($ko) { 'Non conforme' }
              elseif ($ok) { 'Partiel' }
              elseif ($nonApp) { 'Configure mais non applique' }
              else { 'Absent' }
        if ($st -eq 'Absent' -and $m.Defaut) { $st = 'Absent (defaut sur)' }
        $attendu = ($m.R | ForEach-Object { $_.A }) -join ' | '
    }
    $detail = @()
    if ($ko) { $detail += "Non conforme : $($ko -join ', ')" }
    if ($abs -and $m.Mode -ne 'any' -and $st -notlike 'Absent*') { $detail += "Manquant : $($abs -join ', ')" }
    if ($nonApp) { $detail += "Dans une GPO desactivee ou non liee : $($nonApp -join ', ')" }
    if ($m.Defaut -and $st -like 'Absent*') { $detail += "Valeur par defaut : $($m.Defaut) (a verifier sur les systemes anciens)" }
    [pscustomobject]@{
        Mesure = $m.M; Categorie = $m.C; Niveau = $m.N; Statut = $st
        'Valeur constatee' = (($valeurs | Select-Object -Unique) -join ' ; ')
        'Valeur attendue' = $attendu; GPO = (($gposM | Select-Object -Unique) -join ', ')
        Liaisons = (($liaisons -split ', ' | Where-Object { $_ } | Select-Object -Unique) -join ', ')
        Criticite = $m.Cr; Detail = ($detail -join ' | '); Recommandation = $m.Reco
    }
}

# Complement : cles BitLocker sauvegardees dans l'AD (constat reel, au-dela de la GPO)
if (-not $Simu) {
    try {
        $postes = @($Postes | Where-Object { $_.OperatingSystem -match 'Windows' -and $_.PrimaryGroupID -notin 516, 521 })
        $avecCle = @(Get-ADObject -LDAPFilter '(objectClass=msFVE-RecoveryInformation)' -SearchBase $Dom.DistinguishedName |
                     ForEach-Object { ($_.DistinguishedName -split ',', 2)[1] } | Select-Object -Unique)
        $n = @($postes | Where-Object { $avecCle -contains $_.DistinguishedName }).Count
        $p = if ($postes.Count) { [math]::Round(100 * $n / $postes.Count) } else { 0 }
        $Lignes = @($Lignes) + [pscustomobject]@{
            Mesure = 'BitLocker - cles sauvegardees dans l''AD'; Categorie = 'Protection des postes'; Niveau = 'Complement'
            Statut = if ($p -ge 90) { 'En place' } elseif ($n) { 'Partiel' } else { 'Absent' }
            'Valeur constatee' = "$n / $($postes.Count) ordinateur(s) Windows actifs ($p %)"; 'Valeur attendue' = 'Tous les postes et serveurs'
            GPO = ''; Liaisons = ''; Criticite = 3; Detail = 'Ordinateurs ayant au moins une cle de recuperation BitLocker dans l''AD'
            Recommandation = 'Chiffrer les postes avec BitLocker et sauvegarder les cles dans l''AD (ou Entra ID).' }
    } catch { Write-Warning "Lecture des cles BitLocker impossible : $_" }
}

$base = Join-Path $Dossier "$Hote`_Audit_GPO"
$Lignes | Export-Csv -Path "$base`_Referentiel.csv" -NoTypeInformation -Encoding UTF8
$Params | Select-Object Gpo, @{n = 'Etat GPO'; e = { $_.Etat } }, @{n = 'Appliquee'; e = { if ($_.Applique) { 'Oui' } else { 'Non' } } },
    Liens, @{n = 'Portee'; e = { if ($_.Portee -eq 'M') { 'Ordinateur' } else { 'Utilisateur' } } }, Source, Cle,
    @{n = 'Valeur'; e = { $_.Nom } }, @{n = 'Donnee'; e = { "$($_.Valeur)" } } |
    Export-Csv -Path "$base`_Parametres.csv" -NoTypeInformation -Encoding UTF8
$bilan = $Lignes | Group-Object Statut | ForEach-Object { "$($_.Name) : $($_.Count)" }
Write-Host "Referentiel GPO : $($bilan -join ' ; ')"
Write-Host "Export : $base`_Referentiel.csv / _Parametres.csv"
