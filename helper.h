#pragma once

#include <string>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "pcap.h"

class PcapDumper {
 public:
  ~PcapDumper() { Close(); }
  int Open(std::string filename);
  int Close();

  int DumpHexString(uint64_t ts, bool uplink, std::string str);
  // int DumpBase64String(bool uplink, std::string str);

 private:
  pcap_t* handle;
  pcap_dumper_t* dumper;
};
