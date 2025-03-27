#include "netflow.h"
#include <pcap.h>
#include <iostream>
#include <vector>
#include <chrono>
#include <ctime>
#include <cstring>

#define TARGET_BYTES (1250000000ULL) 
#define FIXED_PACKET_SIZE 834
#define RECORD_COUNT 16

const uint8_t ETH_HEADER[14] = {
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x08, 0x00
};

const uint8_t IP_BASE_HEADER[20] = {
    0x45, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x40, 0x00,
    0x40, 0x11, 0x00, 0x00,
    192, 168, 1, 1,
    192, 168, 1, 2
};

const uint8_t UDP_BASE_HEADER[8] = {
    0x04, 0x00,
    0x27, 0x0F,
    0x00, 0x00,
    0x00, 0x00
};

std::vector<uint8_t> createRawPacket(const char* payload, size_t payloadSize)
{
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

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_dead(DLT_EN10MB, 65535);
    pcap_dumper_t *dumper = pcap_dump_open(pcap, "output.pcap");
    if (!dumper)
    {
        std::cerr << "Failed to open pcap file: " << errbuf << std::endl;
        return 1;
    }

    size_t totalBytes = 0;
    std::string payloadBuffer;

    while (totalBytes < TARGET_BYTES)
    {
        std::string ss;
        Netflow netflow = generateNetflow(RECORD_COUNT);
        payloadBuffer = serializeNetFlowData(netflow);

        const char* rawPayload = payloadBuffer.data();
        size_t payloadSize = payloadBuffer.size();

        std::vector<uint8_t> packet = createRawPacket(rawPayload, payloadSize);

        struct pcap_pkthdr header;
        std::time_t now = std::time(nullptr);
        header.ts.tv_sec = now;
        header.ts.tv_usec = 0;
        header.caplen = packet.size();
        header.len = packet.size();

        pcap_dump((u_char *)dumper, &header, packet.data());
        totalBytes += packet.size();
    }

    pcap_dump_close(dumper);
    pcap_close(pcap);

    std::cout << "Done. Wrote " << totalBytes / (1024.0 * 1024.0) << " MB (~"
              << (totalBytes * 8 / 1e9) << " Gbps for ~10s)" << std::endl;

    return 0;
}
