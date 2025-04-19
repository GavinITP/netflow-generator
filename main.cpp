#include "netflow.h"
#include <cstring>
#include <iostream>
#include <pcap.h>
#include <unistd.h>
#include <vector>

#define RECORD_COUNT 30
#define PACKET_COUNT 1024
#define TIME_DELTA_NS 1000000ULL // 1 ms between packets

const uint8_t ETH_HEADER[14] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11,
                                0x22, 0x33, 0x44, 0x55, 0x66, 0x08, 0x00};

const uint8_t IP_BASE_HEADER[20] = {0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
                                    0x00, 0x40, 0x11, 0x00, 0x00, 192,  168,
                                    1,    1,    192,  168,  1,    2};

const uint8_t UDP_BASE_HEADER[8] = {0x04, 0x00, 0x27, 0x0B,
                                    0x00, 0x00, 0x00, 0x00};

std::vector<uint8_t> createRawPacket(const char *payload, size_t payloadSize) {
  std::vector<uint8_t> packet;
  packet.insert(packet.end(), ETH_HEADER, ETH_HEADER + 14);

  uint8_t ip[20];
  std::memcpy(ip, IP_BASE_HEADER, 20);
  uint16_t totalLen = 20 + 8 + payloadSize;
  ip[2] = totalLen >> 8;
  ip[3] = totalLen & 0xFF;
  packet.insert(packet.end(), ip, ip + 20);

  uint8_t udp[8];
  std::memcpy(udp, UDP_BASE_HEADER, 8);
  uint16_t udpLen = 8 + payloadSize;
  udp[4] = udpLen >> 8;
  udp[5] = udpLen & 0xFF;
  packet.insert(packet.end(), udp, udp + 8);

  packet.insert(packet.end(), payload, payload + payloadSize);
  return packet;
}

void generatePcapFile() {
  char filename[64];
  snprintf(filename, sizeof(filename), "%dpackets-%dpdu.pcap", PACKET_COUNT,
           RECORD_COUNT);

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pcap = pcap_open_dead(DLT_EN10MB, 65535);
  pcap_dumper_t *dumper = pcap_dump_open(pcap, filename);
  if (!dumper) {
    std::cerr << "Failed to open " << filename << ": " << errbuf << std::endl;
    return;
  }

  uint64_t sim_ns = 0;
  for (int packetCount = 0; packetCount < PACKET_COUNT; packetCount++) {
    std::vector<NetflowPayload> flows;
    if (sim_ns >= 0ULL && sim_ns < 100000000ULL) {
      for (int i = 0; i < RECORD_COUNT; ++i) {
        flows.push_back(flowSpoofed());
      }
    } else {
      flows = createNetFlowPayload(RECORD_COUNT);
    }

    Netflow netflow;
    netflow.header = createNetFlowHeader(RECORD_COUNT);
    netflow.records = flows;

    std::string payloadBuffer = serializeNetFlowData(netflow);
    const char *rawPayload = payloadBuffer.data();
    size_t payloadSize = payloadBuffer.size();
    std::vector<uint8_t> packet = createRawPacket(rawPayload, payloadSize);

    struct pcap_pkthdr header;
    header.ts.tv_sec = sim_ns / 1000000000;
    header.ts.tv_usec = (sim_ns % 1000000000) / 1000;
    header.caplen = packet.size();
    header.len = packet.size();
    pcap_dump(reinterpret_cast<u_char *>(dumper), &header, packet.data());

    sim_ns += TIME_DELTA_NS;
  }

  pcap_dump_close(dumper);
  pcap_close(pcap);
  std::cout << "Generated " << PACKET_COUNT << " packets.\n";
}

int main() {
  generatePcapFile();
  std::cout << "Generation completed.\n";
  return 0;
}
