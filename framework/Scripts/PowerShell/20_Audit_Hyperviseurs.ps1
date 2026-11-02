# 20_Audit_Hyperviseurs.ps1
# Version      : 1.5
# Derniere modif : Ajout Fabricant, Modele, S/N (Win32_ComputerSystem / Win32_BIOS)
# v1.4         : Colonnes Roles / Integre au domaine / Nb VM hebergees vides dans l'Excel (noms de colonnes
#                  differents du template) : ajout "Nb VM hebergees", domaine en Oui/Non, roles seuls (sans
#                  fonctionnalites), OS reel (Win32_OperatingSystem), Cluster/Standalone conforme a la liste.
#                  Les accents des en-tetes sont ajoutes par modules_config.json (header_map), le script reste ASCII.
# Role         : Inventaire hyperviseur Hyper-V : CPU, RAM, stockage, VMs hebergees, cluster
# Usage        : Lance via main.ps1 ou ansible/audit.yml (profil hyperv). Necessite le role Hyper-V installe.
# ============================================================
$tempCsv      = $env:AUDIT_TEMP_CSV
$cs           = Get-CimInstance Win32_ComputerSystem
$os           = Get-CimInstance Win32_OperatingSystem
$bios         = Get-CimInstance Win32_BIOS
$DomainName   = $cs.Domain
$ComputerName = $env:COMPUTERNAME
$ExportFile   = "$tempCsv\HV\$ComputerName.$DomainName" + "_Audit_Hyperviseurs.csv"
$null = New-Item -ItemType Directory -Force -Path (Split-Path $ExportFile)

# Infos systeme
$cpuNames = (Get-CimInstance Win32_Processor | Select-Object -ExpandProperty Name -Unique) -join " - "
$memGB    = "{0:N2} Go" -f ($cs.TotalPhysicalMemory / 1GB)
$adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
$ipv4     = { $_.IPAddress | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } }
$ipPhys   = ($adapters | Where-Object { $_.Description -notlike "*Hyper-V Virtual Ethernet Adapter*" } | ForEach-Object $ipv4) -join " - "
$ipVeth   = ($adapters | Where-Object { $_.Description -like    "*Hyper-V Virtual Ethernet Adapter*" } | ForEach-Object $ipv4) -join " - "
$macs     = ($adapters.MACAddress | Select-Object -Unique) -join " - "

# Roles installes (pas les fonctionnalites ni les sous-roles)
$roles = try {
    (Get-WindowsFeature -ErrorAction Stop |
        Where-Object { $_.Installed -and $_.FeatureType -eq 'Role' -and -not $_.Parent } |
        Select-Object -ExpandProperty DisplayName) -join " - "
} catch { "Non disponible ($($_.Exception.Message))" }

$domaine = if ($cs.PartOfDomain) { "Oui" } else { "Non" }
$nomDom  = if ($cs.PartOfDomain) { $cs.Domain } else { "WORKGROUP" }

# VMs hebergees
$vms = @()
if (Get-Module -ListAvailable -Name Hyper-V) {
    try { $vms = @(Get-VM -ErrorAction Stop) }
    catch { Write-Warning "Get-VM a echoue : $_" }
} else { Write-Warning "Module Hyper-V indisponible" }
$vmNoms   = ($vms | Sort-Object Name | ForEach-Object { "$($_.Name) ($($_.State))" }) -join " - "
$vmActive = @($vms | Where-Object { $_.State -eq 'Running' }).Count

# Cluster
$cluster = "Standalone"
if (Get-Module -ListAvailable -Name FailoverClusters) {
    try {
        $node = Get-ClusterNode -Name $ComputerName -ErrorAction Stop
        if ($node) { $cluster = "Cluster" ; $nomCluster = [string]$node.Cluster }
    } catch { }
}

$stockage = (Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
    "$($_.DeviceID) $([math]::Round($_.Size / 1GB, 1)) Go (libre : $([math]::Round($_.FreeSpace / 1GB, 1)) Go)"
}) -join " | "

$result = [PSCustomObject]@{
    "Nom"                = $ComputerName
    "IP (Physique)"      = $ipPhys
    "IP (vEthernet)"     = $ipVeth
    "Adresse MAC"        = $macs
    "Roles"              = $roles
    "Type d'hyperviseur" = "Microsoft Hyper-V"
    "OS"                 = $os.Caption
    "Fabricant"          = $cs.Manufacturer
    "Modele"             = $cs.Model
    "S/N"                = $bios.SerialNumber
    "Integre au domaine" = $domaine
    "Nom de Domaine"     = $nomDom
    "Cluster/Standalone" = $cluster
    "Nom du cluster"     = $nomCluster
    "Processeurs"        = $cpuNames
    "RAM"                = $memGB
    "Stockage"           = $stockage
    "Nb VM hebergees"    = $vms.Count
    "Nb VM demarrees"    = $vmActive
    "VMs hebergees"      = $vmNoms
}

$result
$result | Export-Csv -Path $ExportFile -NoTypeInformation -Encoding UTF8