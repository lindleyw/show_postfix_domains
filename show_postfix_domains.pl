#!/usr/bin/perl

# show_postfix_domains.pl
# Looks at /etc/postfix/virtual and tells us which of those emails
# are _actually_ hosted by this system, based on whether DNS lookups of
# the domains seem to point to "us"... where "us" is defined as any
# of the IP addresses on any of localhost's interfaces.
# Naturally, this will fail if your system is behind a gateway/firewall,
# because we have no way of probing that gadget to see how connections
# are routed from "The Internet" to us.

# Copyright (c) 2012, William Lindley wlindley -at- wlindley -dot- com
# 2012-06-06

# This script is free software, you may distribute it and/or modify it
# under the same terms as Perl itself.

use Net::DNS;
use Socket qw/inet_aton/;

use IO::Socket;
use IO::Interface qw(:flags);

my $s = IO::Socket::INET->new(Proto => 'udp');
my @interfaces = $s->if_list;
my %local_interfaces;

for my $if (@interfaces) {
    my $flags = $s->if_flags($if);

    if ( ( $flags & IFF_RUNNING ) && 
	 !( $flags & IFF_LOOPBACK ) &&
	 !( $flags & IFF_NOARP )) {
	$local_interfaces{$if}{address} = $s->if_addr($if);
	$local_interfaces{$s->if_addr($if)}{interface} = $if;
    }
}

#########

my $r = Net::DNS::Resolver->new;

open VIRTUAL, '<', '/etc/postfix/virtual';

my %domains_hosted;

while (<VIRTUAL>) {
    chomp;
    s/\#.*$//;  # Remove after comment
    my ($address, $alias) = split;
    if ($address) {
	if ($alias !~ /@/) { # Only for local addresses (not forwarded)
	    my ($name, $domain) = ($address =~ /^([^@]+)@(.+)$/);
	    next unless $name;
#	    print "[$name]@[$domain] -> [$alias]\n";
	    $domains_hosted{$domain}{hosted} = 1;
	    $domains_hosted{$domain}{address}{$name}++;
	}
    }
}

use Data::Dumper;

foreach my $domain (keys %domains_hosted) {

# Liberally borrowed from David Landgren (grinder)'s code at
# http://www.perlmonks.org/?node_id=297667
    my %res;
    my $rr = $r->query( $domain, 'MX' );
    if ($rr) {
	for my $mx( $rr->answer ) {
            if( $mx->type eq 'CNAME' ) {
                my $a_rr = $r->query( $mx->cname, 'A' );
                if( !$a_rr ) {
                    push @{$res{-1}}, { ip => $mx->cname, forw => $r->
					    errorstring, back => 'CNAME' };
                } else {
                    $_->type eq "A"
                        and push @{$res{-1}}, { ip => $mx->cname, forw => $_->address, back => 'CNAME' }
		    for( $a_rr->answer );
                }
                next;
            }

            next unless $mx->type eq 'MX';

            my $a_rr = $r->query( $mx->exchange, 'A' );

            if( !$a_rr ) {
                push @{$res{$mx->preference ? $mx->preference : 0}}, {
                    ip   => $mx->exchange,
                    forw => $r->errorstring,
                    back => $r->errorstring,
                };
                next;
            }

            my @a;
            for my $a( $a_rr->answer ) {
                next unless $a->type eq "A";

                my $ptr_rr = $r->query( join( '.', reverse( split /\./ , $a->address )) . '.in-addr.arpa', 'PTR' );
		if ($local_interfaces{$a->address}{interface}) {
		    $domains_hosted{$domain}{local}++;
		}
                if( !$ptr_rr ) {
                    push @{$res{$mx->preference}}, {
                        ip => $a->address,
                        forw => $mx->exchange,
                        back => $r->errorstring,
                    };
                } else {
                    foreach ( $ptr_rr->answer ) {
			if ( $_->type eq 'PTR' ) {
			    push @{$res{$mx->preference}}, {
				ip => $a->address,
				forw => lc $mx->exchange,
				back => lc $_->ptrdname,
			    };
			}
		    }
                }
            }

        }
    }
    $domains_hosted{$domain}{mx} = \%res;
}


# This could be greatly expanded by doing more with the data herein:
# print Dumper(%domains_hosted);

print "These email accounts are actually hosted here:\n";

foreach my $domain (sort keys %domains_hosted) {
    next unless $domains_hosted{$domain}{local};
    print $domain . "\n";
    foreach my $email (sort keys %{$domains_hosted{$domain}{address}}) {
	print "   ${email}\@${domain}\n";
    }
}

1;
