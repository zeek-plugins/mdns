########## VARIABLES ##########

global dns_count:  count = 1;
global mdns_count: count = 1;


########## EVENTS ##########

# START
event zeek_init()
    {
    print "########## XIAOMI mDNS TEST START ##########";
    }

event mdns_event(conn: connection)
    {
    print fmt("%d. %s:%s -> %s:%s", mdns_count, conn$id$orig_h, conn$id$orig_p, conn$id$resp_h, conn$id$resp_p);
    mdns_count += 1;
    }

# FINISH
event zeek_done()
    {
    print "########## XIAOMI mDNS TEST STOP ##########";
    }