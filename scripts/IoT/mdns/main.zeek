##! Implements base functionality for mDNS analysis.
##! Generates the mDNS.log file.

module mDNS;

export {
	redef enum Log::ID += { LOG };

	type MdnsLog: record {
		timestamp: time &log;  # Timestamp
		uid:       string  &log;  # Connection unique ID
		id:        conn_id &log;  # Connection 4-tuple of endpoint addresses/ports.
	};

	## Event that can be handled to access the mDNS record as it is sent on
	## to the loggin framework.
	global log_mdns: event(rec: MdnsLog);
}


########## EVENTS ##########

# Triggered when the module is loaded.
# Creates the mDNS log stream.
event zeek_init() &priority=5
	{
	Log::create_stream(mDNS::LOG, [$columns=MdnsLog, $ev=log_mdns, $path="mdns"]);
	}

event mdns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
	{
	Log::write(mDNS::LOG, MdnsLog(
		$timestamp = network_time(),
		$uid = c$uid,
		$id  = c$id
	));
	}
