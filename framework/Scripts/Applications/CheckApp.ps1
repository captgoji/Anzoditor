# Liste les applications installees avec version, date d'installation, editeur,
# utilisateur ayant installe, et ports reseau en ecoute.
# Sortie : CSV separe par ";" sur stdout
#   hostname;name;version;install_date;source;publisher;installed_by;ports_ecoute;exposition;alerte
#
# Applications : cles "Uninstall" du registre (HKLM 64/32 bits + profils HKU).
# Pas de Win32_Product (lent et declenche une reparation MSI).
#
# installed_by (Windows ne stocke pas cette info, on la deduit) :
#  - appli installee dans le profil d'un utilisateur (HKU) -> cet utilisateur
#  - sinon appli MSI -> utilisateur de l'evenement MsiInstaller 1033 (journal Application)
#  - sinon vide
#
# ports_ecoute / exposition :
#  - chaque port TCP en ecoute (et UDP hors plage dynamique 49152-65535) est rattache
#    a l'application dont le dossier d'installation contient l'executable du processus
#    ex. "tcp:443 (nginx), tcp:127.0.0.1:5432 (postgres)"
#    "tcp:443" = ecoute sur toutes les interfaces ; sinon l'adresse est precisee
#  - exposition = RESEAU si au moins un port ecoute ailleurs que sur 127.0.0.1/::1,
#    LOCAL si uniquement en local, vide si aucun port
#  - les processus qui ne correspondent a aucune application (services Windows :
#    svchost, lsass, dns, System pour SMB/HTTP.sys/WinRM...) sortent sur des lignes
#    a part avec source = "processus"
#  NB : "en ecoute sur le reseau" ne veut pas dire "joignable" : le pare-feu peut bloquer.
#
# PHP et Node.js (colonne alerte) : chaque php.exe / php-cgi.exe / node.exe trouve
#   (Program Files, C:\php, xampp, wamp, DoliWamp, nvm, IIS FastCGI, processus en cours,
#   applis qui embarquent leur propre node.exe...) sort sur sa propre ligne :
#     source = php | nodejs
#     alerte = OK / VULNERABLE (corrige en x.y.z) / FIN DE VIE / A VERIFIER,
#              + "ACTIF" si le binaire tourne (avec la commande lancee)
#   PHP     : PHP2Shell (CVE-2026-109618), corrige en 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12
#   Node.js : CVE-2026-111497 (Brotli, RCE, publiee le 21/10/2026),
#             corrige en 22.23.4 / 24.22.1 / 26.12.1 ; 20.x et avant = fin de vie
#   Les applis PHP connues (WordPress, GLPI, Dolibarr...) sortent avec source = appli-php.

$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$hostName = $env:COMPUTERNAME
$clean = { param($v) ("$v".Trim() -replace '[;"]', ',') }

# --- Resolution SID -> DOMAINE\utilisateur (avec cache) ----------------------
$sidCache = @{}
function Resolve-Sid($sid) {
    if (-not $sid) { return '' }
    if ($sidCache.ContainsKey($sid)) { return $sidCache[$sid] }
    try {
        $n = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
    } catch { $n = $sid }
    $sidCache[$sid] = $n
    return $n
}

# --- Installations MSI : produit -> utilisateur (evenement le plus recent) ----
$msiUser = @{}
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'MsiInstaller'; Id = 1033 } |
    ForEach-Object {
        $prod = "$($_.Properties[0].Value)".Trim()
        if ($prod -and -not $msiUser.ContainsKey($prod) -and $_.UserId) {
            $msiUser[$prod] = Resolve-Sid $_.UserId.Value
        }
    }

function Format-InstallDate($raw) {
    if (-not $raw) { return '' }
    $raw = "$raw".Trim()
    foreach ($f in 'yyyyMMdd', 'yyyy-MM-dd', 'dd/MM/yyyy', 'MM/dd/yyyy') {
        $d = [datetime]::MinValue
        if ([datetime]::TryParseExact($raw, $f, [Globalization.CultureInfo]::InvariantCulture, 'None', [ref]$d)) {
            return $d.ToString('yyyy-MM-dd')
        }
    }
    return $raw
}

# --- 1. Applications installees ------------------------------------------------
$paths = @(
    @{ Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*';             Src = 'HKLM64'; Sid = $null },
    @{ Path = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; Src = 'HKLM32'; Sid = $null }
)
if (-not (Get-PSDrive -Name HKU)) { New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null }
Get-ChildItem 'HKU:\' | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } | ForEach-Object {
    $paths += @{ Path = "HKU:\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"; Src = 'HKU'; Sid = $_.PSChildName }
}

$apps = New-Object System.Collections.ArrayList
foreach ($p in $paths) {
    Get-ItemProperty -Path $p.Path |
        Where-Object { $_.DisplayName -and $_.SystemComponent -ne 1 -and -not $_.ParentKeyName -and -not $_.ReleaseType } |
        ForEach-Object {
            $name = "$($_.DisplayName)".Trim()
            if ($p.Sid)                          { $who = Resolve-Sid $p.Sid }
            elseif ($msiUser.ContainsKey($name)) { $who = $msiUser[$name] }
            else                                 { $who = '' }
            $loc = "$($_.InstallLocation)".Trim().Trim('"').TrimEnd('\')
            if ($loc.Length -le 3) { $loc = '' }   # ignore "C:\" ou vide
            [void]$apps.Add([pscustomobject]@{
                hostname     = $hostName
                name         = & $clean $name
                version      = & $clean $_.DisplayVersion
                install_date = Format-InstallDate $_.InstallDate
                source       = $p.Src
                publisher    = & $clean $_.Publisher
                installed_by = & $clean $who
                ports_ecoute = ''
                exposition   = ''
                _loc         = $loc
                _rawname     = $name
            })
        }
}

# --- 2. Ports en ecoute ------------------------------------------------------------
$procs = @{}
Get-CimInstance Win32_Process | ForEach-Object { $procs[[int]$_.ProcessId] = $_ }
$svcByPid = @{}
Get-CimInstance Win32_Service -Filter "State='Running'" | ForEach-Object {
    $k = [int]$_.ProcessId
    if (-not $svcByPid.ContainsKey($k)) { $svcByPid[$k] = @() }
    $svcByPid[$k] += $_.Name
}

$listen = @()
if (Get-Command Get-NetTCPConnection) {
    Get-NetTCPConnection -State Listen | ForEach-Object {
        $listen += [pscustomobject]@{ Proto = 'tcp'; Addr = $_.LocalAddress; Port = [int]$_.LocalPort; ProcId = [int]$_.OwningProcess }
    }
    Get-NetUDPEndpoint | Where-Object { $_.LocalPort -lt 49152 } | ForEach-Object {
        $listen += [pscustomobject]@{ Proto = 'udp'; Addr = $_.LocalAddress; Port = [int]$_.LocalPort; ProcId = [int]$_.OwningProcess }
    }
} else {
    # Windows 2008 R2 : pas de Get-NetTCPConnection -> netstat
    netstat -ano | ForEach-Object {
        $l = $_.Trim() -split '\s+'
        if ($l[0] -eq 'TCP' -and $l[3] -eq 'LISTENING') { $ep = $l[1]; $pp = $l[4]; $pr = 'tcp' }
        elseif ($l[0] -eq 'UDP' -and $l.Count -ge 4)   { $ep = $l[1]; $pp = $l[3]; $pr = 'udp' }
        else { return }
        $i = $ep.LastIndexOf(':')
        $port = [int]$ep.Substring($i + 1)
        if ($pr -eq 'udp' -and $port -ge 49152) { return }
        $listen += [pscustomobject]@{ Proto = $pr; Addr = $ep.Substring(0, $i).Trim('[', ']'); Port = $port; ProcId = [int]$pp }
    }
}

$extra = @{}   # processus sans application -> ligne "processus"
$exePorts = @{}   # chemin exe -> ports (pour les lignes PHP / Node.js)
function Add-Port($obj, $entry, $expo) {
    $list = @(); if ($obj.ports_ecoute) { $list = $obj.ports_ecoute -split ', ' }
    if ($list -notcontains $entry) { $obj.ports_ecoute = (($list + $entry) -join ', ') }
    if ($expo -eq 'RESEAU' -or -not $obj.exposition) { $obj.exposition = $expo }
}

foreach ($e in $listen) {
    $addr = "$($e.Addr)" -replace '%.*$', ''
    if ($addr -match '^(127\.|::1$|::ffff:127\.)') { $expo = 'LOCAL' } else { $expo = 'RESEAU' }
    if ('0.0.0.0', '::', '*' -contains $addr) { $where = '' } elseif ($addr -like '*:*') { $where = "[${addr}]:" } else { $where = "${addr}:" }

    $proc = $procs[$e.ProcId]
    $exe  = "$($proc.ExecutablePath)"
    if ($e.ProcId -eq 4) { $pname = 'System' } elseif ($proc) { $pname = ($proc.Name -replace '\.exe$', '') } else { $pname = "pid $($e.ProcId)" }
    $label = $pname
    if ($svcByPid.ContainsKey($e.ProcId)) { $label = "$pname/" + ($svcByPid[$e.ProcId] -join '+') }
    $entry = "$($e.Proto):$where$($e.Port) ($label)"
    if ($exe) {
        $k = $exe.ToLower()
        if (-not $exePorts.ContainsKey($k)) { $exePorts[$k] = [pscustomobject]@{ ports_ecoute = ''; exposition = '' } }
        Add-Port $exePorts[$k] $entry $expo
    }

    # Rattachement a une application : dossier d'installation, puis nom de produit de l'exe
    $app = $null
    if ($exe) {
        $app = $apps | Where-Object { $_._loc -and $exe.StartsWith($_._loc + '\', [StringComparison]::OrdinalIgnoreCase) } |
               Sort-Object { $_._loc.Length } -Descending | Select-Object -First 1
        if (-not $app) {
            $prodName = "$((Get-Item -LiteralPath $exe).VersionInfo.ProductName)".Trim()
            if ($prodName -and $prodName -notmatch 'Windows.*Operating System') {
                $app = $apps | Where-Object { $_._rawname -eq $prodName -or $_._rawname -like "$prodName*" } | Select-Object -First 1
            }
        }
    }

    if ($app) {
        Add-Port $app $entry $expo
    } else {
        $key = if ($exe) { $exe.ToLower() } else { $pname }
        if (-not $extra.ContainsKey($key)) {
            $leaf = if ($exe) { Split-Path $exe -Leaf } else { $pname }
            $extra[$key] = [pscustomobject]@{
                hostname = $hostName; name = & $clean $leaf; version = ''; install_date = ''
                source = 'processus'; publisher = & $clean $exe; installed_by = ''
                ports_ecoute = ''; exposition = ''; _loc = ''; _rawname = ''
            }
        }
        Add-Port $extra[$key] $entry $expo
    }
}

# --- 3. PHP et Node.js -------------------------------------------------------------
$phpFixed  = @{ '8.2' = 35; '8.3' = 36; '8.4' = 27; '8.5' = 12 }
$nodeFixed = @{ '22' = '22.23.4'; '24' = '24.22.1'; '26' = '26.12.1' }
function Get-VulnStatus([string]$kind, [string]$v) {
    if ($v -notmatch '^(\d+)\.(\d+)\.(\d+)') { return 'A VERIFIER (version illisible)' }
    $maj = [int]$Matches[1]; $min = [int]$Matches[2]; $pat = [int]$Matches[3]
    if ($kind -eq 'php') {
        if ($maj -lt 8 -or ($maj -eq 8 -and $min -lt 2)) { return "FIN DE VIE PHP $maj.$min - plus de correctif" }
        if ($phpFixed.ContainsKey("$maj.$min")) {
            if ($pat -ge $phpFixed["$maj.$min"]) { return 'OK' }
            return "VULNERABLE PHP2Shell CVE-2026-109618 (corrige en $maj.$min.$($phpFixed["$maj.$min"]))"
        }
    } else {
        if ($maj -lt 22 -or ($maj % 2 -eq 1 -and $maj -lt 27)) { return "FIN DE VIE Node $maj - plus de correctif" }
        if ($nodeFixed.ContainsKey("$maj")) {
            if ([version]$Matches[0] -ge [version]$nodeFixed["$maj"]) { return 'OK' }
            return "VULNERABLE CVE-2026-111497 (corrige en $($nodeFixed["$maj"]))"
        }
    }
    return 'A VERIFIER (branche non listee)'
}

# Dossiers ou chercher php.exe / php-cgi.exe / node.exe
$roots = @('C:\php', 'C:\Program Files', 'C:\Program Files (x86)', 'C:\ProgramData\nvm', 'C:\ProgramData\chocolatey\lib', 'C:\xampp', 'C:\wamp', 'C:\wamp64',
           'C:\laragon', 'C:\dolibarr', 'C:\inetpub', 'C:\tools', 'C:\Apache24', 'C:\nginx', 'C:\nvm4w', 'D:\', 'E:\')
$roots += @(Get-ChildItem 'C:\Users' -Directory | ForEach-Object {
    "$($_.FullName)\AppData\Roaming\nvm"; "$($_.FullName)\AppData\Local\Programs"; "$($_.FullName)\AppData\Local\nvs" })
$runtimeExe = @{}   # chemin (minuscules) -> note
foreach ($r in ($roots | Where-Object { Test-Path $_ })) {
    Get-ChildItem -Path $r -Include php.exe, php-cgi.exe, php-win.exe, node.exe -Recurse -File -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\node_modules\\' } |
        ForEach-Object { $runtimeExe[$_.FullName.ToLower()] = '' }
}
# processus en cours (php / node lances depuis n'importe ou)
$procByExe = @{}
foreach ($pr in $procs.Values) {
    if (-not $pr.ExecutablePath) { continue }
    $k = $pr.ExecutablePath.ToLower()
    if (-not $procByExe.ContainsKey($k)) { $procByExe[$k] = @() }
    $procByExe[$k] += $pr
    if ($pr.Name -match '^(php|php-cgi|php-win|node)\.exe$') { $runtimeExe[$k] = '' }
}
# IIS : applications FastCGI declarees (ex : C:\php\php-cgi.exe)
$appcmd = "$env:windir\System32\inetsrv\appcmd.exe"
if (Test-Path $appcmd) {
    $fcgi = (& $appcmd list config -section:system.webServer/fastCgi 2>$null) -join "`n"
    foreach ($mm in [regex]::Matches($fcgi, 'fullPath="([^"]+)"')) { $runtimeExe[$mm.Groups[1].Value.ToLower()] = ' - declare dans IIS FastCGI' }
}

$runtimes = foreach ($k in $runtimeExe.Keys) {
    $f = Get-Item -LiteralPath $k
    if (-not $f) { continue }
    if ($f.Name -ieq 'node.exe') { $kind = 'node'; $label = 'Node.js' } else { $kind = 'php'; $label = 'PHP' }
    $v = "$($f.VersionInfo.ProductVersion)"
    if ($v -notmatch '^\d+\.\d+\.\d+') {
        if ($kind -eq 'node') { $v = "$(& $f.FullName --version 2>$null)".Trim().TrimStart('v') }
        elseif ($f.Name -ieq 'php.exe') { $v = "$(& $f.FullName -n -r 'echo PHP_VERSION;' 2>$null)".Trim() }
    }
    if ($v -match '^(\d+\.\d+\.\d+)') { $v = $Matches[1] } else { continue }
    $st = (Get-VulnStatus $kind $v) + $runtimeExe[$k]
    if ($procByExe.ContainsKey($k)) {
        $cmd = "$($procByExe[$k][0].CommandLine)"
        if ($cmd.Length -gt 100) { $cmd = $cmd.Substring(0, 100) }
        $st += " - ACTIF ($($procByExe[$k].Count) processus : $cmd)"
    }
    $pp = $exePorts[$k]
    [pscustomobject]@{
        hostname = $hostName; name = $label; version = $v; install_date = $f.LastWriteTime.ToString('yyyy-MM-dd')
        source = $(if ($kind -eq 'node') { 'nodejs' } else { 'php' }); publisher = & $clean $f.FullName; installed_by = ''
        ports_ecoute = $(if ($pp) { $pp.ports_ecoute } else { '' }); exposition = $(if ($pp) { $pp.exposition } else { '' })
        alerte = & $clean $st
    }
}

# Applications PHP connues dans les dossiers web
$webRoots = @('C:\inetpub\wwwroot', 'C:\inetpub\vhosts', 'C:\xampp\htdocs', 'C:\wamp\www', 'C:\wamp64\www', 'C:\laragon\www',
              'C:\Apache24\htdocs', 'C:\nginx\html', 'C:\dolibarr\www', 'D:\www', 'D:\inetpub', 'E:\www') | Where-Object { Test-Path $_ }
$markers = [ordered]@{
    'wp-config.php' = 'WordPress'; 'inc\define.php' = 'GLPI'; 'occ' = 'Nextcloud / ownCloud'; 'administrator\manifests' = 'Joomla'
    'sites\default\settings.php' = 'Drupal'; 'app\etc\env.php' = 'Magento'; 'config\settings.inc.php' = 'PrestaShop'
    'artisan' = 'Laravel'; 'bin\console' = 'Symfony'; 'program\lib\Roundcube' = 'Roundcube'
    'libraries\classes\Config.php' = 'phpMyAdmin'; 'htdocs\main.inc.php' = 'Dolibarr'
}
$phpApps = foreach ($root in $webRoots) {
    $cands = @(Get-Item $root) + @(Get-ChildItem $root -Directory) + @(Get-ChildItem $root -Directory | ForEach-Object { Get-ChildItem $_.FullName -Directory })
    foreach ($dir in $cands) {
        foreach ($mk in $markers.Keys) {
            if (Test-Path (Join-Path $dir.FullName $mk)) {
                [pscustomobject]@{ hostname = $hostName; name = $markers[$mk]; version = ''; install_date = ''; source = 'appli-php'
                                   publisher = & $clean $dir.FullName; installed_by = ''; ports_ecoute = ''; exposition = ''; alerte = '' }
                break
            }
        }
    }
}

# --- 4. Sortie CSV -------------------------------------------------------------------
$cols = 'hostname', 'name', 'version', 'install_date', 'source', 'publisher', 'installed_by', 'ports_ecoute', 'exposition', 'alerte'
$out  = @($apps | Sort-Object name, version, installed_by -Unique) + @($extra.Values | Sort-Object name) +
        @($runtimes | Sort-Object name, publisher) + @($phpApps | Sort-Object publisher -Unique)
$out |
    Select-Object $cols |
    ConvertTo-Csv -Delimiter ';' -NoTypeInformation |
    ForEach-Object { $_ -replace '"', '' } |
    Write-Output