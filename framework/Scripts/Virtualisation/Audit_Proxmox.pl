#!/usr/bin/perl
# Audit_Proxmox.pl
# Version      : 1.0
# Derniere modif : Creation - audit Proxmox VE en lecture seule (pvesh), lance sur chaque noeud par audit.yml
# Role         : Sur un serveur Linux de l'inventaire : ne fait rien si ce n'est pas un Proxmox VE (pas de pvesh).
#                Sinon, ecrit sur la sortie standard 4 CSV separes par "#### FICHIER:<nom>" :
#                  HV        meme format que 20_Audit_Hyperviseurs (Hyper-V) -> classeur Hyperviseurs
#                  VMs       VM et conteneurs du noeud : etat, OS, ressources, agent, snapshots, sauvegardes
#                  Stockage  stockages du noeud et remplissage
#                  Securite  version / fin de support, abonnement et depots, mises a jour, comptes et double
#                            authentification, pare-feu, taches de sauvegarde, cluster
# Usage        : par audit.yml (play Linux, avec sudo : pvesh exige root), ou a la main : sudo perl Audit_Proxmox.pl
#                Ecrit en Perl : toujours present sur Proxmox VE (avec son module JSON), rien a installer.
# ============================================================
use strict;
use utf8;
use warnings;

my $PVESH = $ENV{PVESH} || '/usr/bin/pvesh';
exit 0 unless -x $PVESH;
if ($> != 0) { print "#### ERREUR:sudo requis pour pvesh (Proxmox non audite)\n"; exit 0; }
require JSON;
my $J = JSON->new->utf8;
binmode STDOUT, ':encoding(UTF-8)';

# Fin de support Proxmox VE (date estimee publiee par Proxmox, a mettre a jour)
my %FIN = (5 => '2020-07-31', 6 => '2022-07-31', 7 => '2024-07-31', 8 => '2026-08-31', 9 => '2028-08-31');
my ($SNAP_J, $STOCK_PCT, $SAUV_J) = (7, 85, 7);
my $maintenant = time;

sub api {
    my ($chemin, @opts) = @_;
    my $cmd = join ' ', map { my $x = $_; $x =~ s/'/'\\''/g; "'$x'" } ($PVESH, 'get', $chemin, @opts, '--output-format', 'json');
    my $out = `$cmd 2>/dev/null`;
    return undef if $? != 0 || !defined $out || $out eq '';
    my $r = eval { $J->decode($out) };
    return $r;
}
sub liste { my $r = api(@_); return ref $r eq 'ARRAY' ? @$r : (); }
sub go { my $o = shift // 0; return sprintf('%.1f', $o / 1024**3); }
sub dte { my $t = shift; return '' unless $t; my @l = localtime($t); return sprintf('%02d/%02d/%04d %02d:%02d:%02d', $l[3], $l[4] + 1, $l[5] + 1900, $l[2], $l[1], $l[0]); }
sub csvl { return join(';', map { my $v = $_ // ''; $v =~ s/"/""/g; $v =~ s/[\r\n]+/ /g; "\"$v\"" } @_) . "\n"; }
sub lire { my $f = shift; open(my $h, '<', $f) or return ''; my $v = <$h> // ''; close $h; $v =~ s/^\s+|\s+$//g; return $v; }

my $noeud = `hostname -s`; chomp $noeud;
my @noeuds = liste('/nodes');
$noeud = $noeuds[0]{node} if @noeuds == 1 && !grep { $_->{node} eq $noeud } @noeuds;

# ─── Version / cluster ─────────────────────────────────────
my $pvever = `pveversion 2>/dev/null`; chomp $pvever;
my ($majeur) = $pvever =~ m{pve-manager/(\d+)\.};
my ($cluster, $quorum, $nb_noeuds) = ('', '', scalar @noeuds);
for my $c (liste('/cluster/status')) {
    if (($c->{type} // '') eq 'cluster') { $cluster = $c->{name}; $quorum = $c->{quorate}; $nb_noeuds = $c->{nodes}; }
}
my $hv = $cluster ? "cluster:$cluster" : $noeud;

my @sec;
sub sec { push @sec, [@_]; }
{
    my ($st, $com) = ('Info', 'Version non référencée : vérifier le support éditeur');
    if ($majeur && $FIN{$majeur}) {
        my ($a, $m, $j) = split /-/, $FIN{$majeur};
        require Time::Local;
        my $fin = Time::Local::timelocal(0, 0, 0, $j, $m - 1, $a);
        my $jours = int(($fin - $maintenant) / 86400);
        ($st, $com) = $jours < 0 ? ('Critique', "Fin de support le $j/$m/$a : plus de correctifs de sécurité")
                    : $jours < 180 ? ('Attention', "Fin de support le $j/$m/$a (dans $jours j)")
                    : ('OK', "Supporté jusqu'au $j/$m/$a (date estimée)");
    }
    sec($noeud, 'Version', $pvever, $st, $com);
}
sec($hv, 'Cluster', $cluster ? "$cluster ($nb_noeuds noeud(s))" : 'Noeud isolé',
    ($cluster && !$quorum) ? 'Critique' : 'Info', ($cluster && !$quorum) ? 'Cluster sans quorum' : '') if $cluster;

# ─── Noeud ─────────────────────────────────────────────────
my $st = api("/nodes/$noeud/status") || {};
my $ci = $st->{cpuinfo} || {};
my $mem = ($st->{memory} || {})->{total};
my $uptime = $st->{uptime} // 0;
sec($noeud, 'Dernier redémarrage', 'il y a ' . int($uptime / 86400) . ' j', $uptime > 365 * 86400 ? 'Attention' : 'Info',
    $uptime > 365 * 86400 ? "Plus d'un an sans redémarrage : noyau et correctifs probablement pas appliqués" : '');

my $abo = api("/nodes/$noeud/subscription") || {};
my $abo_ok = ($abo->{status} // '') =~ /^active$/i;
sec($noeud, 'Abonnement', $abo_ok ? "Actif ($abo->{level})" : 'Aucun', 'Info', $abo_ok ? ($abo->{productname} // '') : '');
my $rep = api("/nodes/$noeud/apt/repositories") || {};
my (@actifs);
for my $f (@{ $rep->{files} || [] }) {
    for my $r (@{ $f->{repositories} || [] }) {
        next unless $r->{Enabled};
        my $u = join(' ', @{ $r->{URIs} || [] }) . ' ' . join(' ', @{ $r->{Components} || [] });
        push @actifs, 'enterprise' if $u =~ /enterprise\.proxmox\.com/ && $u =~ /pve-enterprise/;
        push @actifs, 'no-subscription' if $u =~ /pve-no-subscription/;
        push @actifs, 'test' if $u =~ /pvetest|pve-test/;
    }
}
my %vu; @actifs = grep { !$vu{$_}++ } @actifs;
my $dep_st = (grep { $_ eq 'enterprise' } @actifs) && !$abo_ok ? 'Attention'
           : (grep { $_ eq 'test' } @actifs) ? 'Attention' : !@actifs ? 'Attention' : 'OK';
sec($noeud, 'Dépôts de mises à jour', join(', ', @actifs) || 'Aucun dépôt Proxmox actif', $dep_st,
    $dep_st eq 'OK' ? '' : (grep { $_ eq 'enterprise' } @actifs) && !$abo_ok
        ? 'Dépôt enterprise sans abonnement : aucune mise à jour Proxmox ne peut être installée'
        : (grep { $_ eq 'test' } @actifs) ? 'Dépôt de test actif en production' : 'Aucune source de mises à jour Proxmox');
my @maj = liste("/nodes/$noeud/apt/update");
sec($noeud, 'Mises à jour en attente', scalar(@maj) . ' paquet(s)', @maj ? 'Attention' : 'OK',
    @maj ? join(', ', map { "$_->{Package} $_->{Version}" } grep { ($_->{Package} // '') =~ /^(pve-|proxmox-|qemu-server|lxc-pve)/ } @maj[0 .. ($#maj < 30 ? $#maj : 29)]) : '');

# ─── Comptes et double authentification ────────────────────
my %tfa;
for my $t (liste('/access/tfa')) { $tfa{ $t->{userid} } = scalar @{ $t->{entries} || [] } if $t->{userid}; }
my @users = grep { $_->{enable} // 1 } liste('/access/users');
my @admins;
for my $a (liste('/access/acl')) {
    push @admins, $a->{ugid} if ($a->{roleid} // '') eq 'Administrator' && ($a->{type} // '') eq 'user';
}
my %adm = map { $_ => 1 } (@admins, 'root@pam');
my @sans = map { $_->{userid} } grep { !$tfa{ $_->{userid} } } @users;
my @adm_sans = grep { $adm{$_} } @sans;
sec($hv, 'Double authentification', scalar(@users) . ' compte(s) actif(s), ' . scalar(@sans) . ' sans double authentification',
    @adm_sans ? 'Attention' : 'OK', @adm_sans ? 'Administrateurs sans double authentification : ' . join(', ', @adm_sans)
    : (@sans ? 'Sans double authentification : ' . join(', ', @sans) : ''));
sec($hv, 'Comptes', join(', ', map { $_->{userid} } @users), 'Info', 'Administrateurs : ' . join(', ', sort keys %adm));

my $fw = api('/cluster/firewall/options') || {};
sec($hv, 'Pare-feu Proxmox', ($fw->{enable} ? 'Activé' : 'Désactivé'), $fw->{enable} ? 'OK' : 'Info',
    $fw->{enable} ? '' : "Pare-feu intégré désactivé : l'accès à l'interface (8006) et à SSH dépend du réseau");

# ─── Sauvegardes ───────────────────────────────────────────
my @jobs = grep { $_->{enabled} // 1 } liste('/cluster/backup');
my %non_sauv = map { $_->{vmid} => 1 } liste('/cluster/backup-info/not-backed-up');
my @stockages = liste("/nodes/$noeud/storage");
my %derniere;
for my $s (grep { ($_->{content} // '') =~ /backup/ && ($_->{active} // 1) } @stockages) {
    for my $b (liste("/nodes/$noeud/storage/$s->{storage}/content", '--content', 'backup')) {
        my $id = $b->{vmid} or next;
        $derniere{$id} = $b->{ctime} if ($b->{ctime} // 0) > ($derniere{$id} // 0);
    }
}
sec($hv, 'Tâches de sauvegarde', scalar(@jobs) . ' tâche(s) active(s)', @jobs ? 'OK' : 'Critique',
    @jobs ? join(' | ', map { ($_->{schedule} // $_->{starttime} // '') . ' -> ' . ($_->{storage} // '') . ' : '
                              . ($_->{all} ? 'toutes les VM' : ($_->{vmid} // $_->{pool} // '')) } @jobs)
          : 'Aucune sauvegarde planifiée');

# ─── VM et conteneurs du noeud ─────────────────────────────
my @vm_l;
my ($nb_vm, $nb_on, @noms) = (0, 0);
for my $r (sort { $a->{vmid} <=> $b->{vmid} } grep { ($_->{node} // '') eq $noeud && !$_->{template} }
           liste('/cluster/resources', '--type', 'vm')) {
    my $type = $r->{type} eq 'lxc' ? 'Conteneur' : 'VM';
    my $chem = "/nodes/$noeud/$r->{type}/$r->{vmid}";
    my $cfg = api("$chem/config") || {};
    my @snaps = grep { ($_->{name} // '') ne 'current' } liste("$chem/snapshot");
    my ($vieux) = sort { $a <=> $b } map { $_->{snaptime} // $maintenant } @snaps;
    my $age = defined $vieux ? int(($maintenant - $vieux) / 86400) : '';
    my $on = ($r->{status} // '') eq 'running';
    $nb_vm++; $nb_on++ if $on;
    push @noms, ($r->{name} // $r->{vmid}) . ($on ? ' (Running)' : ' (Off)');
    my $dern = $derniere{ $r->{vmid} };
    my $planif = $non_sauv{ $r->{vmid} } ? 'Non' : @jobs ? 'Oui' : 'Non';
    my @al;
    push @al, 'Aucune sauvegarde planifiée' if $planif eq 'Non';
    push @al, 'Dernière sauvegarde il y a ' . int(($maintenant - $dern) / 86400) . ' j'
        if $planif eq 'Oui' && $dern && $maintenant - $dern > $SAUV_J * 86400;
    push @al, "Snapshot de $age j" if $age ne '' && $age > $SNAP_J;
    push @al, 'Agent invité désactivé' if $type eq 'VM' && $on && !(($cfg->{agent} // '') =~ /^(1|enabled=1)/);
    push @vm_l, [$hv, $noeud, $r->{name} // '', $r->{vmid}, $type, $on ? 'Démarrée' : ($r->{status} // ''),
                 $cfg->{ostype} // '', $r->{maxcpu} // '', go($r->{maxmem}), go($r->{maxdisk}),
                 ($cfg->{onboot} ? 'Oui' : 'Non'),
                 $type eq 'VM' ? (($cfg->{agent} // '') =~ /^(1|enabled=1)/ ? 'QEMU agent activé' : 'Non') : '-',
                 $cfg->{machine} // '', scalar @snaps, $age, dte($dern), $planif, '', join(' | ', @al)];
}

# ─── Stockage ──────────────────────────────────────────────
my @st_l;
my @resume;
for my $s (grep { $_->{enabled} // 1 } @stockages) {
    my ($tot, $used) = ($s->{total} // 0, $s->{used} // 0);
    my $p = $tot ? sprintf('%.1f', 100 * $used / $tot) : '';
    push @st_l, [$hv, $noeud, $s->{storage}, $s->{type}, ($s->{shared} ? 'Oui' : 'Non'), go($tot), go($used), $p,
                 ($p ne '' && $p > $STOCK_PCT) ? "Rempli à plus de $STOCK_PCT %" : (($s->{active} // 1) ? '' : 'Inactif')];
    push @resume, "$s->{storage} " . go($tot) . ' Go (libre : ' . go($tot - $used) . ' Go)' if $tot;
}

# ─── Reseau / materiel ─────────────────────────────────────
my @ips = map { "$_->{iface} $_->{cidr}" } grep { $_->{cidr} } liste("/nodes/$noeud/network");

# ─── Sortie ────────────────────────────────────────────────
print "#### FICHIER:HV\n";
print csvl('Nom', 'IP (Physique)', 'IP (vEthernet)', 'Adresse MAC', 'Roles', "Type d'hyperviseur", 'OS',
           'Integre au domaine', 'Nom de Domaine', 'Cluster/Standalone', 'Nom du cluster', 'Processeurs', 'RAM',
           'Stockage', 'Nb VM hebergees', 'Nb VM demarrees', 'VMs hebergees', 'Fabricant', 'Modele', 'S/N');
print csvl($noeud, join(' - ', @ips), '', '', $cluster ? "Noeud du cluster $cluster" : 'Noeud isolé', 'Proxmox VE',
           $pvever, '', '', $cluster ? 'Cluster' : 'Standalone', $cluster,
           ($ci->{sockets} // '?') . ' x ' . ($ci->{model} // '') . ' (' . ($ci->{cpus} // '?') . ' threads)',
           sprintf('%.0f Go', ($mem // 0) / 1024**3), join(' | ', @resume), $nb_vm, $nb_on, join(' - ', @noms),
           lire('/sys/class/dmi/id/sys_vendor'), lire('/sys/class/dmi/id/product_name'),
           lire('/sys/class/dmi/id/product_serial'));
print "#### FICHIER:VMs\n";
print csvl('Hyperviseur', 'Hote', 'VM', 'ID', 'Type', 'Etat', 'OS', 'vCPU', 'RAM (Go)', 'Disque (Go)', 'Demarrage auto',
           'Agent invite', 'Version materielle', 'Snapshots', 'Plus ancien snapshot (j)', 'Derniere sauvegarde',
           'Sauvegarde planifiee', 'IP', 'Alerte');
print csvl(@$_) for @vm_l;
print "#### FICHIER:Stockage\n";
print csvl('Hyperviseur', 'Hote', 'Stockage', 'Type', 'Partage', 'Taille (Go)', 'Utilise (Go)', 'Utilise (%)', 'Alerte');
print csvl(@$_) for @st_l;
print "#### FICHIER:Securite\n";
print csvl('Hyperviseur', 'Controle', 'Valeur', 'Statut', 'Commentaire');
print csvl(@$_) for @sec;
exit 0;
