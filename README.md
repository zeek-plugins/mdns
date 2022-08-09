# Multicast DNS (mDNS) package for Zeek IDS


This repository contains a [Zeek](https://zeek.org/) package for the [Multicast DNS (mDNS) protocol](https://en.wikipedia.org/wiki/Multicast_DNS).
The package can be easily installed with [Zeek Package Manager](https://docs.zeek.org/projects/package-manager/en/stable/).

Please consult the following RFCs for additional information about the Multicast DNS protocol:
- DNS: [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035)
- Multicast DNS: [RFC 6762](https://datatracker.ietf.org/doc/html/rfc6762)


## Installation

### Prerequisites

Before trying to install the package, make sure you have the following tools installed:

- [Zeek](https://zeek.org/)
- [Zeek Package Manager](https://docs.zeek.org/projects/package-manager/en/stable/) command `zkg`

Everything should be installed correctly if you install the latest [Zeek](https://zeek.org/) version.


### Setup

This package will install the `IoT::mDNS` Zeek plugin.

To run unit tests and install the package, run:
```shell
zkg install https://github.com/zeek-plugins/mdns  # to install as super user
zkg --user install https://github.com/zeek-plugins/mdns  # to install in user space
```

You might have to update the `ZEEKPATH` and `ZEEK_PLUGIN_PATH` environmental variables.
To see which value they should take, run the following commands:
```shell
zkg env         # For the super user
zkg --user env  # For a normal user
```

To confirm that installation was successful, you can run the following command:
```shell
zeek -NN | grep mDNS
```


If the command's output shows something similar to
```shell
IoT::mDNS - Multicast DNS (mDNS) package for Zeek (dynamic, version 1.0.0)
```
the package was correctly installed, and you have access to the mDNS package.

In the case of any installation problems, please check the [Zeek Package Manager](https://docs.zeek.org/projects/package-manager/en/stable/) documentation.


## Usage

Once the Zeek package installed, you will have access to mDNS events and logging.

### Events

The plugin defines the following events:

- `event mdns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)`
  - Generated for any mDNS message.
- ``event mdns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string)``
  - Generated for mDNS requests.
- ``event mdns_rejected(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string)``
  - Generated for mDNS replies that reject a query.
- ``event mdns_query_reply(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string)``
  - Generated for each entry in the Question section of a mDNS reply.
- ``event mdns_A_reply (c: connection, msg: dns_msg, ans: dns_answer, a: addr)``
  - Generated for mDNS replies of type *A*.
- ``event mdns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)``
  - Generated for mDNS replies of type *AAAA*.
- ``event mdns_A6_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)``
  - Generated for mDNS replies of type *A6*.
- ``event mdns_NS_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)``
  - Generated for mDNS replies of type *NS*.
- ``event mdns_CNAME_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)``
  - Generated for mDNS replies of type *CNAME*.
- ``event mdns_PTR_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)``
  - Generated for mDNS replies of type *PTR*.
- ``event mdns_SOA_reply(c: connection, msg: dns_msg, ans: dns_answer, soa: dns_soa)``
  - Generated for mDNS replies of type *CNAME*
- ``event mdns_WKS_reply(c: connection, msg: dns_msg, ans: dns_answer)``
  - Generated for mDNS replies of type *WKS*.
- ``event mdns_HINFO_reply(c: connection, msg: dns_msg, ans: dns_answer, cpu: string, os: string)``
  - Generated for mDNS replies of type *HINFO*.
- ``event mdns_MX_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string, preference: count)``
  - Generated for mDNS replies of type *MX*.
- ``event mdns_TXT_reply(c: connection, msg: dns_msg, ans: dns_answer, strs: string_vec)``
  - Generated for mDNS replies of type *TXT*.
- ``event mdns_SPF_reply(c: connection, msg: dns_msg, ans: dns_answer, strs: string_vec)``
  - Generated for mDNS replies of type *SPF*.
- ``event mdns_CAA_reply(c: connection, msg: dns_msg, ans: dns_answer, flags: count, tag: string, value: string)``
  - Generated for mDNS replies of type *CAA* (Certification Authority Authorization).
- ``event mdns_SRV_reply(c: connection, msg: dns_msg, ans: dns_answer, target: string, priority: count, weight: count, p: count)``
  - Generated for mDNS replies of type *SRV*.
- ``event mdns_unknown_reply(c: connection, msg: dns_msg, ans: dns_answer)``
  - Generated for mDNS reply resource records when the type of record is not one that Zeek knows how to parse and generate another more specific event.
- ``event mdns_end(c: connection, msg: dns_msg)``
  - Generated at the end of processing a mDNS packet. This event is the last ``mdns_*`` event that will be raised for a mDNS query/reply and signals that all resource records have been passed on.


Those events are usable directly when the plugin is activated.
If you're using Zeek in bare mode, you will need to explicitly load the plugin.
Due to a [Zeek issue](https://github.com/zeek/zeek/issues/2311),
you cannot load it directly from Zeek scripts, and have the two following possibilities:

- Specify the plugin name, `IoT::mDNS` in command line, when running the script.
For example:
```shell
zeek -b IoT::mDNS YOUR_ZEEK_SCRIPT.zeek
```
- Include the loading directive, `@load-plugin IoT::mDNS`, in an auxiliary Zeek script, and run this script along with your script:
```
zeek -b LOADING_SCRIPT.zeek YOUR_ZEEK_SCRIPT.zeek
```

For more information about the events, please consult Zeek's documentation about [DNS events](https://docs.zeek.org/en/master/scripts/base/bif/plugins/Zeek_DNS.events.bif.zeek.html), which are the unicast equivalent of this plugin's mDNS events.


### Logging

The plugin can automatically log all the mDNS traffic that it sees, in the same way as the Zeek DNS plugin.
This produces the `mdns.log` file, which contains, for each mDNS message seen, the following information:

* `ts`: The earliest time at which a DNS protocol message over the associated connection is observed.
* `uuid`: A unique identifier of the connection over which mDNS messages are being transferred.
* `id`: The connection's 4-tuple of endpoint addresses/ports.

   * `id.orig_h`: The originator's IP address.
   * `id.orig_p`: The originator's port.
   * `id.resp_h`: The responder's IP address.
   * `id.resp_p`: The responder's port.

* `proto`: The transport layer protocol of the connection (always UDP).
* `trans_id`: A 16-bit identifier assigned by the program that generated the DNS query.  Also used in responses to match up replies to outstanding queries.
* `rtt` Round trip time for the query and response. This indicates the delay between when the request was seen until the answer started.
* `query`: The domain name that is the subject of the DNS query.
* `qclass`: The QCLASS value specifying the class of the query.
* `qclass_name`: A descriptive name for the class of the query.
* `qtype`: The QTYPE value specifying the type of the query.
* `qtype_name`: A descriptive name for the type of the query.
* `rcode`: The response code value in DNS response messages.
* `rcode_name`: A descriptive name for the response code value.
* `AA`: The Authoritative Answer bit for response messages specifies that the responding name server is an authority for the domain name in the question section.
* `TC`: The Truncation bit specifies that the message was truncated.
* `RD`: The Recursion Desired bit in a request message indicates that the client wants recursive service for this query.
* `RA`: The Recursion Available bit in a response message indicates that the name server supports recursive queries.
* `Z`: A reserved field that is usually zero in queries and responses.
* `answers`: The set of resource descriptions in the query answer.
* `TTLs`: The caching intervals of the associated RRs described by the *answers* field.
* `rejected`: The DNS query was rejected by the server.


To enable mDNS logging, you will have to explicitly load the package scripts in the beginning of your Zeek scripts, with the following instruction:
```shell
@load /path/to/mDNS/scripts
```

If you updated the `ZEEKPATH` environment variable as explained before, the path should simply be `IoT/mDNS`.


## License

This project is licensed under the BSD license. See the [COPYING](COPYING) file for details.


## Contributors


- François De Keersmaeker
  - GitHub: [@fdekeers](https://github.com/fdekeers>)
  - Email: francois.dekeersmaeker@uclouvain.be

Thanks to the ESnet team for [Zeek Package Cookie Cutter](https://github.com/esnet/cookiecutter-zeekpackage>).
