#include "Plugin.h"

namespace plugin { namespace IoT_mDNS { Plugin plugin; } }

using namespace plugin::IoT_mDNS;

zeek::plugin::Configuration Plugin::Configure()
	{

	zeek::plugin::Configuration config;

	config.name = "IoT::mDNS";
	config.description = "Multicast DNS (mDNS) package for Zeek";

	config.version.major = 1;
	config.version.minor = 0;
	config.version.patch = 0;

	return config;
	}

