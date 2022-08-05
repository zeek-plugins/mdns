# @TEST-DOC: Tests the mDNS plugin on a PCAP file, and verify output.
# @TEST-EXEC: zeek -b ${PLUGIN} %INPUT -r ${TRACES}/mdns-only.pcap

########## EVENTS ##########

# START
event zeek_init()
    {
    print "########## XIAOMI mDNS TEST START ##########";
    }

event mdns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
    {
    ;
    }

# FINISH
event zeek_done()
    {
    print "########## XIAOMI mDNS TEST STOP ##########";
    }
