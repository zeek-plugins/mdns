#include "config.h"
#include "Plugin.h"

namespace zeek::plugin::IoT_mDNS { Plugin plugin; }

using namespace zeek::plugin::IoT_mDNS;

zeek::plugin::Configuration Plugin::Configure()
	{
	zeek::plugin::Configuration config;
	config.name = "IoT::mDNS";
	config.description = "TODO: Insert description";
	config.version.major = VERSION_MAJOR;
	config.version.minor = VERSION_MINOR;
	config.version.patch = VERSION_PATCH;
	return config;
	}
