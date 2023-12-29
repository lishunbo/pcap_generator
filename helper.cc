#include "helper.h"

#include <cstring>
#include <chrono>

#define UDP_HEADER_LEN 8
static uint16_t base_ip_id = 1;

int PcapDumper::Open(std::string filename) {
  int npos = filename.rfind('.');
  filename = filename.substr(0, npos) + ".pcap";

  char errbuf[PCAP_ERRBUF_SIZE];

  handle = pcap_open_dead(DLT_EN10MB, BUFSIZ);  // 创建pcap文件
  // handle = pcap_open_offline("example.pcap", errbuf);  // 打开pcap文件
  // if (handle == NULL) {
  //   fprintf(stderr, "Couldn't open pcap file: %s\n", errbuf);
  //   exit(1);
  // }
  dumper = pcap_dump_open(handle, filename.c_str());
  if (dumper == NULL) {
    fprintf(stderr, "Couldn't open pcap file for writing\n");
    return -1;
  }
  return 0;
}

int PcapDumper::Close() {
  pcap_dump_close(dumper);  // 关闭写入pcap文件的句柄
  pcap_close(handle);       // 关闭pcap文件

  return 0;
}

int PcapDumper::DumpHexString(uint64_t ts, bool uplink, std::string str) {
  auto hexstr2data = [](std::string hexstr) {
    std::string data;
    data.resize(hexstr.length() / 2);

    auto convert = [](char ch) {
      if (ch >= '0' && ch <= '9') {
        return ch - '0';
      }
      return ch - 'a' + 10;
    };

    for (int i = 0; i < hexstr.length() / 2; i++) {
      uint8_t h = convert(hexstr.c_str()[i * 2]);
      uint8_t l = convert(hexstr.c_str()[i * 2 + 1]);

      data.data()[i] = (h << 4) | l;
    }
    return data;
  };
  std::string data = hexstr2data(str);

  // 构造数据包内容
  struct pcap_pkthdr header;

  int total_size = sizeof(struct ether_header) + sizeof(struct iphdr) +
                   UDP_HEADER_LEN + data.length();

  u_char buffer[total_size] = {0};

  struct ether_header* eth_hdr = reinterpret_cast<struct ether_header*>(buffer);
  eth_hdr->ether_type = htons(ETH_P_IP);

  struct iphdr* ip_header =
      reinterpret_cast<struct iphdr*>(buffer + sizeof(struct ether_header));
  memset(ip_header, 0, sizeof(struct iphdr));
  // Fill in the required fields
  ip_header->ihl = 5;  // Header length in 32-bit words (5 * 4 bytes = 20 bytes)
  ip_header->version = 4;  // IPv4
  ip_header->tos = 0;      // Type of Service
  ip_header->tot_len = htons(sizeof(struct iphdr) + UDP_HEADER_LEN +
                             data.length());  // Total length (header + data)
  ip_header->id = htons(base_ip_id++);        // Identification field
  ip_header->frag_off = htons(0x4000);        // Fragmentation flags and offset
  ip_header->ttl = 64;                        // Time to live
  ip_header->protocol =
      IPPROTO_UDP;       // Protocol (e.g., IPPROTO_TCP, IPPROTO_UDP)
  ip_header->check = 0;  // Fill in later
  if (uplink) {
    ip_header->saddr = inet_addr("192.168.0.1");  // Source IP address
    ip_header->daddr = inet_addr("192.168.0.2");  // Destination IP address
  } else {
    ip_header->saddr = inet_addr("192.168.0.2");  // Source IP address
    ip_header->daddr = inet_addr("192.168.0.1");  // Destination IP address
  }

  // 构造UDP包
  struct udphdr* udp_header = reinterpret_cast<struct udphdr*>(
      buffer + sizeof(struct ether_header) + sizeof(struct iphdr));

  if (uplink) {
    udp_header->source = htons(1234);  // 源端口
    udp_header->dest = htons(4321);    // 目标端口
  } else {
    udp_header->source = htons(4321);  // 源端口
    udp_header->dest = htons(1234);    // 目标端口
  }
  udp_header->len = htons(UDP_HEADER_LEN + data.length());  // 长度
  udp_header->check = 0;  // 检验和（可以忽略）

  u_char* udp_data =
      reinterpret_cast<u_char*>(buffer + sizeof(struct ether_header) +
                                sizeof(struct iphdr) + sizeof(struct udphdr));
  memcpy(udp_data, data.c_str(), data.length());

  auto now = std::chrono::system_clock::now();
  header.len = total_size;
  header.caplen = total_size;
  header.ts.tv_sec = ts / 1000000;
  header.ts.tv_usec = ts % 1000000;
  // gettimeofday(&header.ts, nullptr);

  pcap_dump((u_char*)dumper, &header, buffer);  // 将数据包写入文件

  return 0;
}
