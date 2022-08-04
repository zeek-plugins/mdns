#include "mDNS.h"
#include "zeek/Reporter.h"
#include "events.bif.h"

using namespace analyzer::IoT_mDNS;

mDNS_Analyzer::mDNS_Analyzer(zeek::Connection* conn) : zeek::analyzer::tcp::TCP_ApplicationAnalyzer("mDNS", conn)

	{
	dns_analyzer = new ::zeek::analyzer::dns::DNS_Analyzer(conn);
	}

mDNS_Analyzer::~mDNS_Analyzer()
	{
	delete dns_analyzer;
	}

void mDNS_Analyzer::Init()
	{
	dns_analyzer->Init();
	}

void mDNS_Analyzer::Done()
	{
	dns_analyzer->Done();
	}

void mDNS_Analyzer::DeliverPacket(int len, const u_char* data,
	 			                  bool orig, uint64_t seq,
								  const zeek::IP_Hdr* ip, int caplen)
	{
	EnqueueConnEvent(mdns_event, ConnVal());
	dns_analyzer->DeliverPacket(len, data, orig, seq, ip, caplen);
	}

void mDNS_Analyzer::ConnectionClosed(::zeek::analyzer::tcp::TCP_Endpoint* endpoint,
	                                 ::zeek::analyzer::tcp::TCP_Endpoint* peer,
						             bool gen_event)
	{
	dns_analyzer->ConnectionClosed(endpoint, peer, gen_event);
	}

