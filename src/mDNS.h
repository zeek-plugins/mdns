#pragma once

#include "events.bif.h"
#include "zeek/analyzer/protocol/dns/DNS.h"

namespace analyzer {
namespace IoT_mDNS {

class mDNS_Analyzer final : public ::zeek::analyzer::tcp::TCP_ApplicationAnalyzer
	{
public:
	explicit mDNS_Analyzer(zeek::Connection* conn);
	~mDNS_Analyzer() override;
	
	void DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq,
	                   const zeek::IP_Hdr* ip, int caplen) override;

	void Init() override;
	void Done() override;
	void ConnectionClosed(::zeek::analyzer::tcp::TCP_Endpoint* endpoint,
	                      ::zeek::analyzer::tcp::TCP_Endpoint* peer,
						  bool gen_event) override;
	void ExpireTimer(double t);
	
	static ::zeek::analyzer::Analyzer* Instantiate(zeek::Connection* conn)
		{ return new mDNS_Analyzer(conn); }


protected:
	::zeek::analyzer::dns::DNS_Analyzer* dns_analyzer;
	};

} } // namespace analyzer::*
