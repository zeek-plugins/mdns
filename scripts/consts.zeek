##! Constants used by the mDNS plugin.

module mDNS;

export {

    # IPv4 and IPv6 mDNS addresses
    const mdns_addrs: set[addr] = { 224.0.0.251, [ff02::fb] };
    # mDNS port: 5353/udp
    const mdns_port: port = 5353/udp;

}
