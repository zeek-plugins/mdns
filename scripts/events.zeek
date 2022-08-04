##! Events issued by the mDNS plugin,
##! based on the built-in DNS events.

module mDNS;


########## FUNCTIONS ##########

# Checks if a given connection is used for mDNS.
# :param c: the given connection
# :returns: true if the connection is used for mDNS, false otherwise
function is_mdns(c: connection): bool
    {
    return c$id$resp_h in mdns_addrs &&
           c$id$orig_p == mdns_port &&
           c$id$resp_p == mdns_port;
    }


########## EVENTS ##########

# event mdns_message(c: connection, is_orig: bool, msg: dns_msg, len: count);
# Generated for every mDNS message.
# Based on the dns_message event.
event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count) &priority=10
    {
    if ( is_mdns(c) )
        {
        event mdns_message(c, is_orig, msg, len);
        }
    }

# event mdns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count);
# Generated for every mDNS request.
# Based on the dns_request event.
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) &priority=10
    {
    if ( is_mdns(c) )
        {
        event mdns_request(c, msg, query, qtype, qclass);
        }
    }

# event mdns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr);
# Generated for every mDNS reply of type A.
# Based on the dns_A_reply event.
event dns_A_reply (c: connection, msg: dns_msg, ans: dns_answer, a: addr) &priority=10
    {
    if ( is_mdns(c) )
        {
        event mdns_A_reply(c, msg, ans, a);
        }
    }
