##! Implements base functionality for mDNS analysis.
##! Generates the mDNS.log file.

module mDNS;

export {
	redef enum Log::ID += { LOG };

	## Event that can be handled to access the mDNS record as it is sent on
	## to the loggin framework.
	global log_mdns: event(rec: DNS::Info);
}


########## EVENTS ##########

# Triggered when the module is loaded.
# Creates the mDNS log stream.
event zeek_init() &priority=5
	{
	Log::create_stream(mDNS::LOG, [$columns=DNS::Info, $ev=log_mdns, $path="mdns"]);
	}

event mdns_end(c: connection, msg: dns_msg) &priority=-5
	{
	if ( c?$dns )
		{
		Log::write(mDNS::LOG, c$dns);
		}
	}
