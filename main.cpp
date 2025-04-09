#include "netflow.h"
#include <chrono>
#include <cstring>
#include <iostream>
#include <pcap.h>
#include <sstream>
#include <unistd.h>
#include <vector>

#define FIXED_PACKET_SIZE 834
#define RECORD_COUNT 4
#define TARGET_DURATION_SECONDS 1

const uint8_t ETH_HEADER[14] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11,
                                0x22, 0x33, 0x44, 0x55, 0x66, 0x08, 0x00};

const uint8_t IP_BASE_HEADER[20] = {0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
                                    0x00, 0x40, 0x11, 0x00, 0x00, 192,  168,
                                    1,    1,    192,  168,  1,    2};

const uint8_t UDP_BASE_HEADER[8] = {0x04, 0x00, 0x27, 0x0B,
                                    0x00, 0x00, 0x00, 0x00};

std::vector<uint8_t> createRawPacket(const char *payload, size_t payloadSize) {
  std::vector<uint8_t> packet;
  packet.reserve(FIXED_PACKET_SIZE);

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

  if (packet.size() < FIXED_PACKET_SIZE)
    packet.resize(FIXED_PACKET_SIZE, 0x00);

  return packet;
}

void generatePcapFile() {
  char filename[64];
  snprintf(filename, sizeof(filename), "output.pcap");

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pcap = pcap_open_dead(DLT_EN10MB, 65535);
  pcap_dumper_t *dumper = pcap_dump_open(pcap, filename);
  if (!dumper) {
    std::cerr << "Failed to open " << filename << ": " << errbuf << std::endl;
    return;
  }

  std::string payloadBuffer;
  size_t totalBytes = 0;
  size_t packetCount = 0;

  uint64_t target_ns = TARGET_DURATION_SECONDS * 1000000000ULL;
  uint64_t dt =
      (FIXED_PACKET_SIZE * 8) / 10; // dt ~ 667 ns per packet for 10Gbps
  if (dt == 0)
    dt = 1;

  uint64_t nextSpoofTime = rand() % target_ns;

  uint64_t sim_ns = 0;

  while (sim_ns < target_ns) {
    std::vector<NetflowPayload> flows;
    if (sim_ns >= nextSpoofTime) {
      flows.push_back(flowSpoofed());

      for (int i = 1; i < RECORD_COUNT; i++) {
        if (rand() % 2 == 0)
          flows.push_back(flowLtoR());
        else
          flows.push_back(flowRtoL());
      }

      uint64_t remaining = target_ns - sim_ns;
      nextSpoofTime = sim_ns + (rand() % (remaining > 0 ? remaining : 1));
    } else {
      flows = createNetFlowPayload(RECORD_COUNT);
    }

    Netflow netflow;
    netflow.header = createNetFlowHeader(RECORD_COUNT);
    netflow.records = flows;
    payloadBuffer = serializeNetFlowData(netflow);
    const char *rawPayload = payloadBuffer.data();
    size_t payloadSize = payloadBuffer.size();
    std::vector<uint8_t> packet = createRawPacket(rawPayload, payloadSize);

    struct pcap_pkthdr header;
    header.ts.tv_sec = sim_ns / 1000000000;
    header.ts.tv_usec = (sim_ns % 1000000000) / 1000;
    header.caplen = packet.size();
    header.len = packet.size();

    pcap_dump(reinterpret_cast<u_char *>(dumper), &header, packet.data());
    totalBytes += packet.size();
    packetCount++;
    sim_ns += dt;
  }

  pcap_dump_close(dumper);
  pcap_close(pcap);
  double totalBits = totalBytes * 8;
  std::cout << "Generated " << packetCount
            << " packets, simulated throughput: " << (totalBits / 1e9)
            << " Gbps\n";
}

int main() {
  generatePcapFile();
  std::cout << "Generation completed.\n";
  return 0;
}
