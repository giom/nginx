#! /usr/bin/perl
#
use warnings;
use strict;

use Cache::Memcached::Fast;

use FindBin;

@ARGV > 1
  or die "Usage: $FindBin::Script NGINX.CONF FILE...\n";


my $config = shift @ARGV;

open(my $fh, '<', $config)
    or die "open(< $config): $!";

my $nested = 0;
my %conf;
my $weight_scale = 1;
while (my $line = <$fh>) {
    next if $line =~ /^\s*#/;

    chomp $line;

    if ($line =~ /^\s*memcached_hash\b/) {
        $nested = 1;
        $conf{ketama_points} = $1 if $line =~ /\bketama_points=(\d+)/;
        $weight_scale = $1 if $line =~ /\bweight_scale=(\d+)/;
    } elsif ($line =~ /^\s*server\s+(\S+)/) {
        my $addr = $1;
        $addr =~ s/^unix://;
        $addr =~ s/;$//;
        my %server;
        $server{address} = $addr;
        $server{weight} = $1 / $weight_scale if $line =~ /\bweight=(\d+)/;
        push @{$conf{servers}}, \%server;
    } elsif ($line =~ /{/) {
        ++$nested if $nested > 0;
    } elsif ($line =~ /}/) {
        last if $nested > 0 and --$nested == 0;
    }
}

close($fh);


$conf{nowait} = 1;

my $memd = new Cache::Memcached::Fast(\%conf);

foreach (@{$conf{servers}}) {
    print "address => $_->{address}";
    print ", weight => $_->{weight}" if exists $_->{weight};
    print "\n";
}
print "ketama_points => $conf{ketama_points}\n" if exists $conf{ketama_points};

my $version = $memd->server_versions;
die "No server is running at one of addresses\n"
    unless @$version == @{$conf{servers}};

$/ = undef;
foreach my $file (@ARGV) {
    open(my $fh, '<', $file)
        or die "open(< $file): $!";

    $file =~ s|.*/||;
    my $contents = <$fh>;
    $memd->set("/$file", $contents);

    close($fh);
}

# Push all pending requests.
$version = $memd->server_versions;
