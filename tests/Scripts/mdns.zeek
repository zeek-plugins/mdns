########## VARIABLES ##########

global dns_count:  count = 1;
global mdns_count: count = 1;


########## EVENTS ##########

# START
event zeek_init()
    {
    print "########## XIAOMI mDNS TEST START ##########";
    }

event mdns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
    {
    print fmt("%d. %s:%s -> %s:%s", mdns_count, c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    mdns_count += 1;
    }

# FINISH
event zeek_done()
    {
    print "########## XIAOMI mDNS TEST STOP ##########";
    }