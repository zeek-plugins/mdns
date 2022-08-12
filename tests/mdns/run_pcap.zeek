# @TEST-DOC: Tests the mDNS plugin on a PCAP file, and verify output.
# @TEST-EXEC: zeek -b ${PACKAGE} %INPUT -r ${TRACES}/mdns-only.pcap > mdns_only.out
# @TEST-EXEC: btest-diff mdns_only.out
# @TEST-EXEC: zeek -b ${PACKAGE} %INPUT -r ${TRACES}/trace.pcap > trace.out
# @TEST-EXEC: btest-diff trace.out
# @TEST-EXEC: btest-diff mdns.log


# Count of mDNS messages
global mdns_count: count = 1;


########## EVENTS ##########

# START
event zeek_init()
    {
    print "########## mDNS PACKAGE TEST START ##########";
    }

# Triggered by each mDNS message
event mdns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
    {
    print fmt("%d. %s:%s -> %s:%s", mdns_count, c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    mdns_count += 1;
    }

# FINISH
event zeek_done()
    {
    print "########## mDNS PACKAGE TEST STOP ##########";
    }
