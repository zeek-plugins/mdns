##! Implements base functionality for mDNS analysis.
##! Generates the mDNS.log file.

module mDNS;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Timestamp for when the event happened.
		ts:     time    &log;
		## Unique ID for the connection.
		uid:    string  &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:     conn_id &log;
		
		# ## TODO: Add other fields here that you'd like to log.
	};

	## Event that can be handled to access the mDNS record as it is sent on
	## to the loggin framework.
	global log_mdns: event(rec: Info);
}

# TODO: The recommended method to do dynamic protocol detection
# (DPD) is with the signatures in dpd.sig. If you can't come up
# with any signatures, then you can do port-based detection by
# uncommenting the following and specifying the port(s):

# const ports = { 1234/udp, 5678/udp };


# redef likely_server_ports += { ports };

event zeek_init() &priority=5
	{
	#Log::create_stream(mDNS::LOG, [$columns=Info, $ev=log_mdns, $path="mdns"]);

	# TODO: If you're using port-based DPD, uncomment this.
	# Analyzer::register_for_ports(Analyzer::ANALYZER_MDNS, ports);
	}

#event mdns_event(c: connection)
#	{
#	local info: Info;
#	info$ts  = network_time();
#	info$uid = c$uid;
#	info$id  = c$id;
#
#	Log::write(mDNS::LOG, info);
#	}
