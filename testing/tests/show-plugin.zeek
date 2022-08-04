# @TEST-EXEC: zeek -NN IoT::mDNS |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
