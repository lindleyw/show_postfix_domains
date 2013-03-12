show_postfix_domains
====================

Examine /etc/postfix/virtual and see which emails are actually hosted 'here' by doing DNS lookups

Looks at /etc/postfix/virtual and tells us which of those emails are _actually_ hosted by this system, based on whether DNS lookups of the domains seem to point to "us"... where "us" is defined as any of the IP addresses on any of localhost's interfaces.                                                   

Naturally, this will fail if your system is behind a gateway/firewall, because we have no way of probing that gadget to see how connections are routed from "The Internet" to us.
