#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

#include "helper.h"

int main(int argc, char** argv) {
  if (argc != 2) {
    printf("no input file name\n");
    return 0;
  }

  std::ifstream infile(argv[1]);
  if (!infile.is_open()) {
    printf("cannot open input file by name %s\n", argv[1]);
    return -1;
  }
  PcapDumper dumper;
  dumper.Open(argv[1]);

  std::string line;
  uint64_t old_ts = 0;
  uint64_t offset = 0;
  while (std::getline(infile, line)) {
    int pos = line.find(' ');
    std::string ts = line.substr(0, pos);
    // line = line.substr(pos + 1);
    bool uplink = line[pos + 1] == '0';
    pos = line.rfind(' ');
    std::string hexstr = line.substr(pos + 1);
    // std::cout << atol(ts.c_str()) << " " << uplink << " " << hex <<
    // std::endl; break;

    uint64_t new_ts = atol(ts.c_str());
    if (new_ts != old_ts) {
      offset = 0;
    } else {
      offset++;
    }
    old_ts = new_ts;

    dumper.DumpHexString(new_ts * 1000 + offset, uplink, hexstr);
  }

  // dumper.DumpHexString(0, true, "123456");

  return 0;
}