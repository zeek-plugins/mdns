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
    ;
    }

# FINISH
event zeek_done()
    {
    print "########## XIAOMI mDNS TEST STOP ##########";
    }