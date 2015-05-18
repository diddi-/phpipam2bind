#!/usr/bin/env perl


use warnings;
use strict;

use JSON;
use Data::Diff qw(Diff);
use phpipam;
use Net::IP qw(ip_inttobin ip_bintoip ip_is_overlap ip_reverse ip_iptobin);
use Net::DNS::Resolver;
use Net::DNS;

use Data::Dumper;

# Work directory to keep track of changes
my $work_dir = '/tmp/phpipam2bind';

# Nameservers to push changes to
my $nameservers = ['192.168.0.2'];

# Standard DNS TTL
my $dns_ttl = "500";

# DDNS key and name
my $dns_key = "somerandomkey=";
my $dns_key_name = "bind_key";

# DNS domains to update
#
#  NOTE NOTE: phpipam2bind does a somewhat stupid match on all elements in dns_zones array.
#  This means that currently you can't update only records containing the 'mydomain.com' domain
#  without also updating any records in a subdomain of 'mydomain.com'.
#
#  That is, matching _only_ records in phpipam with 'mydomain.com' domain, but _not_ matching 'sub.mydomain.com' is not possible.
########
my $dns_zones = ['mydomain.com'];
my $dns_reverse = {
  '192.168.0.0/24' => '0.0.168.192.in-addr.arpa',
};

# Section name in phpipam from where to fetch addresses
my $phpipam_zones = ['MySection'];

# phpipam database details
my $phpipam_dbhost = "localhost";
my $phpipam_dbname = "phpipam";
my $phpipam_dbuser = "phpipam";
my $phpipam_dbpass = "phpipam";


#########################################################
#
#  Don't touch anything below this comment
#
#########################################################

my $zones = {};
my $old_zones = {};


sub int2ip {
  my $int = shift;

  my $version = length($int) > 10 ? 6 : 4;
  my $binip = ip_inttobin($int, $version);
  my $ip = ip_bintoip($binip, $version);
  return $ip;
}

sub get_reverse_zone {
  my $ip = shift;

  # Weird fkn work-around since perl can't seem to find $dns_reverse at every run...
  my $reverse = $dns_reverse;

  print "get_reverse_zone($ip)\n";
  foreach my $subnet (keys(%{$dns_reverse})) {
    print "Checking if $ip overlaps with $subnet\n";
    my $netip = Net::IP->new($subnet);
    my $version = 4;
    if($ip =~ m/\:/) {
      $version = 6;
    }
    if(ip_is_overlap(ip_iptobin($ip,$version), ip_iptobin($ip,$version), ip_iptobin($netip->ip(),$version), ip_iptobin($netip->last_ip(),$version), $version) == -1) {
      return $dns_reverse->{$subnet};
    }
  }

  return undef;
}

sub search_zones {
  my $addresses = shift;

  foreach my $address (@{$addresses}) {
    foreach my $zone (@{$dns_zones}) {
      my $dns = $address->{'dns_name'};
      my $ip = int2ip($address->{'ip_addr'});

      if($dns =~ m/$zone$/) {
        #print $dns." MATCH ".$zone."\n";
        push(@{$zones->{$zone}->{$dns}->{'data'}}, $ip);
      }
    }
  }

  return 0;
}

sub zones2json {

  foreach my $zone (@{$dns_zones}) {
    my $full_path = $work_dir."/db.$zone.phpipam2bind";
    open(my $dbfile, ">", $full_path);
    if(not $dbfile) {
      die("Unable to open $full_path: $!\n");
    }

    my $output->{$zone} = $zones->{$zone};
    print $dbfile to_json($output, {pretty => 1});
  }

  return 0;
}

sub json2zones {

  foreach my $zone (@{$dns_zones}) {
    my $json;

    my $full_path = $work_dir."/db.$zone.phpipam2bind";
    if(! -e $full_path) {
      return -1;
    }

    open(my $dbfile, "<", $full_path);
    if(not $dbfile) {
      die("Unable to open $full_path: $!\n");
    }
    while(<$dbfile>) {
      $json .= $_;
    }

    my $old_zone = from_json($json);
    while(my($dns, $attr) = each(%{$old_zone})) {
      $old_zones->{$dns} = $old_zone->{$dns};
    }

  }

  return 0;
}

# Get difference between $old_zones and $zones
# and update bind server
sub bind_update {

  my $diff = Diff($old_zones, $zones);
  #print Dumper($diff);

  foreach my $zone (@{$dns_zones}) {

    # Old hostnames to be completely removed
    if($diff->{'diff'}->{$zone}->{'uniq_a'} or $diff->{'uniq_a'}->{$zone}) {
      my @hosts;
      if($diff->{'diff'}->{$zone}->{'uniq_a'}) {
        @hosts = keys($diff->{'diff'}->{$zone}->{'uniq_a'});
      }else{
        @hosts = keys($diff->{'uniq_a'}->{$zone});
      }

      foreach my $host (@hosts) {
        my $data_path;
        if($diff->{'diff'}->{$zone}->{'uniq_a'}) {
          $data_path = $diff->{'diff'}->{$zone}->{'uniq_a'};
        }else{
          $data_path = $diff->{'uniq_a'}->{$zone};
        }

        foreach my $data (@{$data_path->{$host}->{'data'}}) {
          if(nsupdate_del($zone, $host, $data) < 0) {
            $zones->{$zone}->{$host} = $data_path->{$host};
          }
        }
        if(nsupdate_del($zone, $host) < 0) {
          # If we can't remove the DNS record for some reason,
          # add it to our $zones so that we can try again later.
          $zones->{$zone}->{$host} = $data_path->{$host};
        }
      }
    }

    # New hostnames to be added (has never existed before)
    if($diff->{'diff'}->{$zone}->{'uniq_b'} or $diff->{'uniq_b'}->{$zone}) {
      my @hosts;
      if($diff->{'diff'}->{$zone}->{'uniq_b'}) {
        @hosts = keys($diff->{'diff'}->{$zone}->{'uniq_b'});
      }else{
        @hosts = keys($diff->{'uniq_b'}->{$zone});
      }

      foreach my $host (@hosts) {
        my $data_path;
        if($diff->{'diff'}->{$zone}->{'uniq_b'}) {
          $data_path = $diff->{'diff'}->{$zone}->{'uniq_b'};
        }else{
          $data_path = $diff->{'uniq_b'}->{$zone};
        }

        foreach my $data (@{$data_path->{$host}->{'data'}}) {
          my $type = "A";
          if($data =~ m/\:/) {
            $type = "AAAA";
          }
          if(nsupdate_add($zone, $host, $data) < 0) {
            delete $zones->{$zone}->{$host};
          }
        }
      }
    }

    while(my ($host, $attr) = each(%{$diff->{'diff'}->{$zone}->{'diff'}})) {
      # Hostname with data to be deleted
      if($attr->{'diff'}->{'data'}->{'uniq_a'}) {
        foreach my $data (@{$attr->{'diff'}->{'data'}->{'uniq_a'}}) {
          my $type = "A";
          if($data =~ m/\:/) {
            $type = "AAAA";
          }
          if(nsupdate_del($zone, $host, $data) < 0) {
            $zones->{$zone}->{$host} = $host;
          }
        }
      }

      # Hostname with data to be added
      if($attr->{'diff'}->{'data'}->{'uniq_b'}) {
        foreach my $data (@{$attr->{'diff'}->{'data'}->{'uniq_b'}}) {
          my $type = "A";
          if($data =~ m/\:/) {
            $type = "AAAA";
          }
          if(nsupdate_add($zone, $host, $data) < 0) {
            delete $zones->{$zone}->{$host};
          }
        }
      }
    }
  }

  return 0;
}

sub nsupdate_add {
  my $zone = shift;
  my $host = shift;
  my $data = shift;
  my $ptr = undef;

  my $type = "A";
  if($data =~ m/\:/) {
    $type = "AAAA";
  }

  print "nsupdate_add($zone, $host, $data)\n";
  $ptr = get_reverse_zone($data);
  if(not defined $ptr) {
    print "Could not get any reverse zone info for $data\n";
  }else{
    print "($ptr): ".ip_reverse($data)." $dns_ttl PTR $host.\n";
  }

  my $ndu_fwd = Net::DNS::Update->new("$zone.");
  my $ndu_rev = Net::DNS::Update->new("$ptr.") if defined $ptr;

  $ndu_fwd->push(update => rr_add("$host. $dns_ttl $type $data"));
  $ndu_rev->push(update => rr_add(ip_reverse($data)." $dns_ttl PTR $host.")) if defined $ptr;

  my $res = Net::DNS::Resolver->new;
  $res->nameservers(@{$nameservers});

  $ndu_fwd->sign_tsig($dns_key_name, $dns_key);
  $ndu_rev->sign_tsig($dns_key_name, $dns_key) if defined $ptr;

  # We'll only catch one error here...
  my $reply = $res->send($ndu_fwd);
  $reply = $res->send($ndu_rev) if defined $ptr;
  # Check return code
  if ($reply) {
    if ($reply->header->rcode eq 'NOERROR' ) {
      print "Update succeeded\n";
    } else {
      print 'Update failed ', $reply->header->rcode, "\n";
      return -1;
    }
  } else {
      print 'Update failed ', $res->errorstring, "\n";
      return -1;
  }

  print "($zone): update add $host $data\n";
  print "\n";
  return 0;
}

sub nsupdate_del {
  my $zone = shift;
  my $host = shift;
  my $data = shift;
  my $ptr = undef;

  my $type = "A";
  if($data =~ m/\:/) {
    $type = "AAAA";
  }

  if($data) {
    $ptr = get_reverse_zone($data);
    if(not defined $ptr) {
      print "Could not get any reverse zone info for $data\n";
    }
  }

  my $ndu_fwd = Net::DNS::Update->new("$zone.");
  my $ndu_rev = Net::DNS::Update->new("$ptr.") if defined $ptr;

  if($data) {
    $ndu_fwd->push(update => rr_del("$host. $dns_ttl $type $data"));
  }else{
    $ndu_fwd->push(update => rr_del("$host."));
  }
  $ndu_rev->push(update => rr_del(ip_reverse($data)." $dns_ttl PTR $host.")) if defined $ptr;

  my $res = Net::DNS::Resolver->new;
  $res->nameservers(@{$nameservers});

  $ndu_fwd->sign_tsig($dns_key_name, $dns_key);
  $ndu_rev->sign_tsig($dns_key_name, $dns_key) if defined $ptr;

  # We'll only catch one error here...
  my $reply = $res->send($ndu_fwd);
  $reply = $res->send($ndu_rev) if defined $ptr;

  # Check return code
  if ($reply) {
    if ($reply->header->rcode eq 'NOERROR' ) {
      print "Update succeeded\n";
    } else {
      print 'Update failed ', $reply->header->rcode, "\n";
      return -1;
    }
  } else {
      print 'Update failed ', $res->errorstring, "\n";
      return -1;
  }

  print "($zone): update del $host $data\n";

  return 0;

}

sub main {

  if(not -e $work_dir) {
    die("Could not open working directory $work_dir: $!\n");
  }

  my $ipam = phpipam->new(
    dbhost => $phpipam_dbhost,
    dbuser => $phpipam_dbuser,
    dbpass => $phpipam_dbpass,
    dbname => $phpipam_dbname,
  );

  foreach my $ipam_zone (@{$phpipam_zones}) {
    search_zones($ipam->getAddresses({section => $ipam_zone}));
  }

  json2zones();
  bind_update();
  zones2json();
  return 0;
}
main();
