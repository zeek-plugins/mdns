##! Events issued by the mDNS plugin,
##! based on the built-in DNS events.


########## EVENT DECLARATIONS ##########

export {

    # Generated for every mDNS message.
    global mdns_message: event(c: connection, is_orig: bool, msg: dns_msg, len: count);

    # Generated for every mDNS request.
    global mdns_request: event(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string);

    # Generated for mDNS replies that reject a query. This event is raised if a mDNS
    # reply indicates failure because it does not pass on any
    # answers to a query. Note that all of the event's parameters are parsed out of
    # the reply; there's no stateful correlation with the query.
    global mdns_rejected: event(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string);

    # Generated for each entry in the Question section of a mDNS reply.
    global mdns_query_reply: event(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string);

    # Generated for mDNS replies of type A.
    global mdns_A_reply : event(c: connection, msg: dns_msg, ans: dns_answer, a: addr);

    # Generated for mDNS replies of type *AAAA*. For replies with multiple answers,
    # an individual event of the corresponding type is raised for each.
    global mdns_AAAA_reply: event(c: connection, msg: dns_msg, ans: dns_answer, a: addr);

    # Generated for mDNS replies of type *A6*. For replies with multiple answers, an
    # individual event of the corresponding type is raised for each.
    global mdns_A6_reply: event(c: connection, msg: dns_msg, ans: dns_answer, a: addr);

    # Generated for mDNS replies of type *NS*. For replies with multiple answers, an
    # individual event of the corresponding type is raised for each.
    global mdns_NS_reply: event(c: connection, msg: dns_msg, ans: dns_answer, name: string);

    # Generated for mDNS replies of type *CNAME*. For replies with multiple answers,
    # an individual event of the corresponding type is raised for each.
    global mdns_CNAME_reply: event(c: connection, msg: dns_msg, ans: dns_answer, name: string);

    # Generated for mDNS replies of type *PTR*. For replies with multiple answers, an
    # individual event of the corresponding type is raised for each.
    global mdns_PTR_reply: event(c: connection, msg: dns_msg, ans: dns_answer, name: string);

    # Generated for mDNS replies of type *SOA*. For replies with multiple answers, an
    # individual event of the corresponding type is raised for each.
    global mdns_SOA_reply: event(c: connection, msg: dns_msg, ans: dns_answer, soa: dns_soa);

    # Generated for mDNS replies of type *WKS*. For replies with multiple answers, an
    # individual event of the corresponding type is raised for each.
    global mdns_WKS_reply: event(c: connection, msg: dns_msg, ans: dns_answer);

    # Generated for mDNS replies of type *HINFO*. For replies with multiple answers, an
    # individual event of the corresponding type is raised for each.
    global mdns_HINFO_reply: event(c: connection, msg: dns_msg, ans: dns_answer, cpu: string, os: string);

    # Generated for mDNS replies of type *MX*. For replies with multiple answers, an
    # individual event of the corresponding type is raised for each.
    global mdns_MX_reply: event(c: connection, msg: dns_msg, ans: dns_answer, name: string, preference: count);

    # Generated for mDNS replies of type *TXT*. For replies with multiple answers, an
    # individual event of the corresponding type is raised for each.
    global mdns_TXT_reply: event(c: connection, msg: dns_msg, ans: dns_answer, strs: string_vec);

    # Generated for mDNS replies of type *SPF*. For replies with multiple answers, an
    # individual event of the corresponding type is raised for each.
    global mdns_SPF_reply: event(c: connection, msg: dns_msg, ans: dns_answer, strs: string_vec);

    # Generated for mDNS replies of type *CAA*. For replies with multiple answers, an
    # individual event of the corresponding type is raised for each.
    global mdns_CAA_reply: event(c: connection, msg: dns_msg, ans: dns_answer, flags: count, tag: string, value: string);

    # Generated for mDNS replies of type *SRV*. For replies with multiple answers, an
    # individual event of the corresponding type is raised for each.
    global mdns_SRV_reply: event(c: connection, msg: dns_msg, ans: dns_answer, target: string, priority: count, weight: count, p: count);

    # Generated on mDNS reply resource records when the type of record is not one
    # that Zeek knows how to parse and generate another more specific event.
    global mdns_unknown_reply: event(c: connection, msg: dns_msg, ans: dns_answer);

    # Generated at the end of processing a mDNS packet. This event is the last
    # ``mdns_*`` event that will be raised for a mDNS query/reply and signals that
    # all resource records have been passed on.
    global mdns_end: event(c: connection, msg: dns_msg);

}

########## FUNCTIONS ##########

# Checks if a given connection is used for mDNS.
# :param c: the given connection
# :return: T if the connection is used for mDNS, F otherwise
function is_mdns(c: connection): bool
    {
    return (c$id$resp_h in mDNS::mdns_addrs &&
           c$id$orig_p == mDNS::mdns_port &&
           c$id$resp_p == mDNS::mdns_port);
    }


########## EVENT IMPLEMENTATIONS ##########

# event mdns_message(c: connection, is_orig: bool, msg: dns_msg, len: count);
# Generated for every mDNS message.
# Based on the dns_message event.
event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
    {
    if ( is_mdns(c) )
        {
        event mdns_message(c, is_orig, msg, len);
        }
    }

# event mdns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string);
# Generated for every mDNS request.
# Based on the dns_request event.
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string)
    {
    if ( is_mdns(c) )
        {
        event mdns_request(c, msg, query, qtype, qclass, original_query);
        }
    }

# event mdns_rejected(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string);
# Generated for mDNS replies that reject a query. This event is raised if a mDNS
# reply indicates failure because it does not pass on any
# answers to a query. Note that all of the event's parameters are parsed out of
# the reply; there's no stateful correlation with the query.
# Based on the dns_rejected event.
event dns_rejected(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string)
    {
    if ( is_mdns(c) )
        {
        event mdns_rejected(c, msg, query, qtype, qclass, original_query);
        }
    }

# event mdns_query_reply(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string);
# Generated for each entry in the Question section of a mDNS reply.
# Based on the dns_query_reply event.
event dns_query_reply(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string)
    {
    if ( is_mdns(c) )
        {
        event mdns_query_reply(c, msg, query, qtype, qclass, original_query);
        }
    }

# event mdns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr);
# Generated for mDNS replies of type A.
# Based on the dns_A_reply event.
event dns_A_reply (c: connection, msg: dns_msg, ans: dns_answer, a: addr)
    {
    if ( is_mdns(c) )
        {
        event mdns_A_reply(c, msg, ans, a);
        }
    }

# event mdns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr);
# Generated for mDNS replies of type *AAAA*. For replies with multiple answers,
# an individual event of the corresponding type is raised for each.
# Based on the dns_AAAA_reply event.
event dns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
    {
    if ( is_mdns(c) )
        {
        event mdns_AAAA_reply(c, msg, ans, a);
        }
    }

# event mdns_A6_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr);
# Generated for mDNS replies of type *A6*. For replies with multiple answers, an
# individual event of the corresponding type is raised for each.
# Based on the dns_A6_reply event.
event dns_A6_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
    {
    if ( is_mdns(c) )
        {
        event mdns_A6_reply(c, msg, ans, a);
        }
    }

# event mdns_NS_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string);
# Generated for mDNS replies of type *NS*. For replies with multiple answers, an
# individual event of the corresponding type is raised for each.
# Based on the dns_NS_reply event.
event dns_NS_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
    {
    if ( is_mdns(c) )
        {
        event mdns_NS_reply(c, msg, ans, name);
        }
    }

# event mdns_CNAME_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string);
# Generated for mDNS replies of type *CNAME*. For replies with multiple answers,
# an individual event of the corresponding type is raised for each.
# Based on the dns_CNAME_reply event.
event dns_CNAME_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
    {
    if ( is_mdns(c) )
        {
        event mdns_CNAME_reply(c, msg, ans, name);
        }
    }

# event mdns_PTR_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string);
# Generated for mDNS replies of type *PTR*. For replies with multiple answers, an
# individual event of the corresponding type is raised for each.
# Based on the dns_PTR_reply event.
event dns_PTR_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
    {
    if ( is_mdns(c) )
        {
        event mdns_PTR_reply(c, msg, ans, name);
        }
    }

# event mdns_SOA_reply(c: connection, msg: dns_msg, ans: dns_answer, soa: dns_soa);
# Generated for mDNS replies of type *SOA*. For replies with multiple answers, an
# individual event of the corresponding type is raised for each.
# Based on the dns_SOA_reply event.
event dns_SOA_reply(c: connection, msg: dns_msg, ans: dns_answer, soa: dns_soa)
    {
    if ( is_mdns(c) )
        {
        event mdns_SOA_reply(c, msg, ans, soa);
        }
    }

# event mdns_WKS_reply(c: connection, msg: dns_msg, ans: dns_answer);
# Generated for mDNS replies of type *WKS*. For replies with multiple answers, an
# individual event of the corresponding type is raised for each.
# Based on the dns_WKS_reply event.
event dns_WKS_reply(c: connection, msg: dns_msg, ans: dns_answer)
    {
    if ( is_mdns(c) )
        {
        event mdns_WKS_reply(c, msg, ans);
        }
    }

# event mdns_HINFO_reply(c: connection, msg: dns_msg, ans: dns_answer, cpu: string, os: string);
# Generated for mDNS replies of type *HINFO*. For replies with multiple answers, an
# individual event of the corresponding type is raised for each.
# Based on the dns_HINFO_reply event.
event dns_HINFO_reply(c: connection, msg: dns_msg, ans: dns_answer, cpu: string, os: string)
    {
    if ( is_mdns(c) )
        {
        event mdns_HINFO_reply(c, msg, ans, cpu, os);
        }
    }

# event mdns_MX_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string, preference: count);
# Generated for mDNS replies of type *MX*. For replies with multiple answers, an
# individual event of the corresponding type is raised for each.
# Based on the dns_MX_reply event.
event dns_MX_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string, preference: count)
    {
    if ( is_mdns(c) )
        {
        event mdns_MX_reply(c, msg, ans, name, preference);
        }
    }

# event mdns_TXT_reply(c: connection, msg: dns_msg, ans: dns_answer, strs: string_vec);
# Generated for mDNS replies of type *TXT*. For replies with multiple answers, an
# individual event of the corresponding type is raised for each.
# Based on the dns_TXT_reply event.
event dns_TXT_reply(c: connection, msg: dns_msg, ans: dns_answer, strs: string_vec)
    {
    if ( is_mdns(c) )
        {
        event mdns_TXT_reply(c, msg, ans, strs);
        }
    }

# event mdns_SPF_reply(c: connection, msg: dns_msg, ans: dns_answer, strs: string_vec);
# Generated for mDNS replies of type *SPF*. For replies with multiple answers, an
# individual event of the corresponding type is raised for each.
# Based on the dns_SPF_reply event.
event dns_SPF_reply(c: connection, msg: dns_msg, ans: dns_answer, strs: string_vec)
    {
    if ( is_mdns(c) )
        {
        event mdns_SPF_reply(c, msg, ans, strs);
        }
    }

# event mdns_CAA_reply(c: connection, msg: dns_msg, ans: dns_answer, flags: count, tag: string, value: string);
# Generated for mDNS replies of type *CAA*. For replies with multiple answers, an
# individual event of the corresponding type is raised for each.
# Based on the dns_CAA_reply event.
event dns_CAA_reply(c: connection, msg: dns_msg, ans: dns_answer, flags: count, tag: string, value: string)
    {
    if ( is_mdns(c) )
        {
        event mdns_CAA_reply(c, msg, ans, flags, tag, value);
        }
    }

# event mdns_SRV_reply(c: connection, msg: dns_msg, ans: dns_answer, target: string, priority: count, weight: count, p: count);
# Generated for mDNS replies of type *SRV*. For replies with multiple answers, an
# individual event of the corresponding type is raised for each.
# Based on the dns_SRV_reply event.
event dns_SRV_reply(c: connection, msg: dns_msg, ans: dns_answer, target: string, priority: count, weight: count, p: count)
    {
    if ( is_mdns(c) )
        {
        event mdns_SRV_reply(c, msg, ans, target, priority, weight, p);
        }
    }

# event mdns_unknown_reply(c: connection, msg: dns_msg, ans: dns_answer);
# Generated on mDNS reply resource records when the type of record is not one
# that Zeek knows how to parse and generate another more specific event.
# Based on the dns_unknown_reply event.
event dns_unknown_reply(c: connection, msg: dns_msg, ans: dns_answer)
    {
    if ( is_mdns(c) )
        {
        event mdns_unknown_reply(c, msg, ans);
        }
    }

# event mdns_end(c: connection, msg: dns_msg);
# Generated at the end of processing a mDNS packet. This event is the last
# ``mdns_*`` event that will be raised for a mDNS query/reply and signals that
# all resource records have been passed on.
# Based on the dns_end event.
event dns_end(c: connection, msg: dns_msg)
    {
    if ( is_mdns(c) )
        {
        event mdns_end(c, msg);
        }
    }
