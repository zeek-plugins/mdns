#include "Plugin.h"

namespace plugin { namespace IoT_mDNS { Plugin plugin; } }

using namespace plugin::IoT_mDNS;

zeek::plugin::Configuration Plugin::Configure()
	{

	zeek::plugin::Configuration config;

	config.name = "IoT::mDNS";
	config.description = "Multicast DNS (mDNS) Protocol Analyzer for Zeek IDS";

	config.version.major = 0;
	config.version.minor = 1;
	config.version.patch = 0;

	return config;
	}

