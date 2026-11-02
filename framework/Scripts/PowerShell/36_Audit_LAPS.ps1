# 36_Audit_LAPS.ps1
# Version      : 1.0
# Derniere modif : Creation
# Role         : LAPS dans l'Active Directory : pour chaque ordinateur actif, presence d'un mot de passe
#                administrateur local gere (Windows LAPS : msLAPS-PasswordExpirationTime, ou LAPS historique :
#                ms-Mcs-AdmPwdExpirationTime) et date d'expiration. Aucun mot de passe n'est lu.
# Usage        : Lance via main.ps1 ou ansible/audit.yml (profil dc_principal). Necessite RSAT AD.
# Sortie       : AD\<HOTE>.<domaine>_Audit_LAPS.csv
# ============================================================
$OutputEncoding = [System.Text.Encoding]::UTF8
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
Import-Module ActiveDirectory -ErrorAction Stop

$tempCsv    = $env:AUDIT_TEMP_CSV
$DomainName = (Get-CimInstance Win32_ComputerSystem).Domain
$ExportFile = "$tempCsv\AD\$env:COMPUTERNAME.$DomainName" + "_Audit_LAPS.csv"
$null = New-Item -ItemType Directory -Force -Path (Split-Path $ExportFile)
$JoursRetard = 7     # mot de passe expire depuis plus de N jours = rotation bloquee

# Attributs presents dans le schema ?
$schema = (Get-ADRootDSE).schemaNamingContext
$aSchema = { param($n) [bool](Get-ADObject -SearchBase $schema -LDAPFilter "(lDAPDisplayName=$n)" -ErrorAction SilentlyContinue) }
$winLaps = & $aSchema 'msLAPS-PasswordExpirationTime'
$oldLaps = & $aSchema 'ms-Mcs-AdmPwdExpirationTime'
Write-Host "Schema : Windows LAPS = $winLaps ; LAPS historique = $oldLaps"

$props = @('OperatingSystem', 'LastLogonDate', 'Enabled', 'PrimaryGroupID', 'whenCreated')
if ($winLaps) { $props += 'msLAPS-PasswordExpirationTime' }
if ($oldLaps) { $props += 'ms-Mcs-AdmPwdExpirationTime' }

function Depuis-FileTime($v) {
    if ($null -eq $v -or "$v" -eq '' -or [int64]"$v" -le 0) { return $null }
    try { return [DateTime]::FromFileTime([int64]"$v") } catch { return $null }
}

$maintenant = Get-Date
$res = foreach ($c in Get-ADComputer -Filter * -Properties $props) {
    $os = "$($c.OperatingSystem)"
    $estDC = $c.PrimaryGroupID -in 516, 521
    $type = if ($estDC) { 'Controleur de domaine' } elseif ($os -match 'Server') { 'Serveur' }
            elseif ($os -match 'Windows') { 'Poste' } else { 'Autre' }
    $expW = if ($winLaps) { Depuis-FileTime $c.'msLAPS-PasswordExpirationTime' }
    $expO = if ($oldLaps) { Depuis-FileTime $c.'ms-Mcs-AdmPwdExpirationTime' }
    $laps = if ($expW) { 'Windows LAPS' } elseif ($expO) { 'LAPS historique' } else { 'Aucun' }
    $exp  = if ($expW) { $expW } else { $expO }

    $alerte = ''
    if (-not $c.Enabled) { $alerte = '' }
    elseif ($estDC) { $laps = 'Non applicable (DC)' }
    elseif ($type -eq 'Autre') { $alerte = '' }
    elseif ($laps -eq 'Aucun') { $alerte = 'Sans LAPS : mot de passe administrateur local non gere' }
    elseif ($exp -and $exp -lt $maintenant.AddDays(-$JoursRetard)) {
        $alerte = "Mot de passe expire depuis $([int]($maintenant - $exp).TotalDays) j : rotation bloquee"
    }
    if ($laps -eq 'LAPS historique' -and -not $alerte -and $c.Enabled) { $alerte = 'LAPS historique (migrer vers Windows LAPS)' }

    [PSCustomObject]@{
        Ordinateur         = $c.Name
        Type               = $type
        OS                 = $os
        Actif              = if ($c.Enabled) { 'Oui' } else { 'Non' }
        DerniereConnexion  = if ($c.LastLogonDate) { $c.LastLogonDate.ToString('dd/MM/yyyy HH:mm:ss') } else { '' }
        OU                 = ($c.DistinguishedName -split ',', 2)[1]
        LAPS               = $laps
        ExpirationMdp      = if ($exp) { $exp.ToString('dd/MM/yyyy HH:mm:ss') } else { '' }
        Alerte             = $alerte
    }
}

$res | Sort-Object @{e={$_.Alerte -eq ''}}, Type, Ordinateur |
    Export-Csv -Path $ExportFile -NoTypeInformation -Encoding UTF8
$sans = @($res | Where-Object { $_.Alerte -like 'Sans LAPS*' }).Count
Write-Host "Export LAPS : $ExportFile ($(@($res).Count) ordinateurs, $sans sans LAPS)"
