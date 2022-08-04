# Signature for Multicast DNS (mDNS) messages

signature dpd_mdns {
	
	dst-ip == 224.0.0.251,[ff02::fb]
	src-port == 5353
	dst-port == 5353
	ip-proto == udp

	enable "mDNS"

}
