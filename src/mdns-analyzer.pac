# Generated by binpac_quickstart

refine flow mDNS_Flow += {
	function proc_mdns_message(msg: mDNS_PDU): bool
		%{
		zeek::BifEvent::enqueue_mdns_event(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn());
		return true;
		%}
};

refine typeattr mDNS_PDU += &let {
	proc: bool = $context.flow.proc_mdns_message(this);
};
