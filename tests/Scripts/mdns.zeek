########## VARIABLES ##########

global dns_count:  count = 1;
global mdns_count: count = 1;


########## EVENTS ##########

# START
event zeek_init()
    {
    print "########## XIAOMI mDNS TEST START ##########";
    }

event mdns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
    {
    print "A reply", ans;
    }

# FINISH
event zeek_done()
    {
    print "########## XIAOMI mDNS TEST STOP ##########";
    }