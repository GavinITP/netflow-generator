#include "netflow.h"
#include "utils.h"

#include <arpa/inet.h>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <vector>

enum Port {
  FTP_PORT = 21,
  SSH_PORT = 22,
  DNS_PORT = 53,
  HTTP_PORT = 80,
  HTTPS_PORT = 443,
  NTP_PORT = 123,
  SNMP_PORT = 161,
  IMAPS_PORT = 993,
  MYSQL_PORT = 3306,
  HTTPS_ALT_PORT = 8080,
  P2P_PORT = 6681,
  BITTORRENT_PORT = 6682
};

enum PayloadSize { PAYLOAD_AVG_MD = 1024, PAYLOAD_AVG_SM = 256 };

long long startTime = std::chrono::duration_cast<std::chrono::nanoseconds>(
                          std::chrono::steady_clock::now().time_since_epoch())
                          .count();
uint32_t sysUptime = 0;
uint32_t flowSequence = 0;

NetflowHeader createNetFlowHeader(int recordCount) {
  auto now = std::chrono::steady_clock::now();
  auto duration = now.time_since_epoch();
  long long t =
      std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count();

  uint32_t sec = static_cast<uint32_t>(t / 1000000000);
  uint32_t nsec = static_cast<uint32_t>(t - (sec * 1000000000));
  sysUptime = static_cast<uint32_t>((t - startTime) / 1000000) + 1000;

  flowSequence++;

  NetflowHeader header;
  header.version = 5;
  header.flowCount = static_cast<uint16_t>(recordCount);
  header.sysUptime = sysUptime;
  header.unixSec = sec;
  header.unixMsec = nsec;
  header.flowSequence = flowSequence;
  header.engineType = 1;
  header.engineId = 0;
  header.sampleInterval = 0;

  return header;
}

NetflowPayload flowLtoR() {
  NetflowPayload payload;
  int leftHost = rand() % (254 - 130 + 1) + 130;
  int rightHost = rand() % (126 - 2 + 1) + 2;
  char lIP[16], rIP[16];

  snprintf(lIP, sizeof(lIP), "192.168.191.%d", leftHost);
  snprintf(rIP, sizeof(rIP), "192.168.191.%d", rightHost);

  payload.srcIp = ipToUint32(std::string(lIP));
  payload.dstIp = ipToUint32(std::string(rIP));
  payload.nextHopIp = ipToUint32("192.168.191.129");

  payload.srcPort = static_cast<uint16_t>(rand() % 64512 + 1024);
  payload.dstPort = HTTP_PORT;

  payload.snmpInIndex = 2;
  payload.snmpOutIndex = 3;

  fillCommonFields(payload, PAYLOAD_AVG_MD, 6, rand() % 32);
  return payload;
}

NetflowPayload flowRtoL() {
  NetflowPayload payload;
  int rightHost = rand() % (126 - 2 + 1) + 2;
  int leftHost = rand() % (254 - 130 + 1) + 130;
  char rIP[16], lIP[16];

  snprintf(rIP, sizeof(rIP), "192.168.191.%d", rightHost);
  snprintf(lIP, sizeof(lIP), "192.168.191.%d", leftHost);

  payload.srcIp = ipToUint32(std::string(rIP));
  payload.dstIp = ipToUint32(std::string(lIP));
  payload.nextHopIp = ipToUint32("192.168.191.1");

  payload.srcPort = static_cast<uint16_t>(rand() % 64512 + 1024);
  payload.dstPort = HTTP_PORT;

  payload.snmpInIndex = 3;
  payload.snmpOutIndex = 2;

  fillCommonFields(payload, PAYLOAD_AVG_MD, 6, rand() % 32);
  return payload;
}

NetflowPayload flowSpoofed() {
  NetflowPayload payload;
  bool spoofFromRight = rand() % 2 == 0;

  if (spoofFromRight) {
    // IP from right side, but appears to come from left
    int rightHost = rand() % (126 - 2 + 1) + 2;
    char spoofIP[16];
    snprintf(spoofIP, sizeof(spoofIP), "192.168.191.%d", rightHost);
    payload.srcIp = ipToUint32(std::string(spoofIP));

    int leftHost = rand() % (254 - 130 + 1) + 130;
    char dstIP[16];
    snprintf(dstIP, sizeof(dstIP), "192.168.191.%d", leftHost);
    payload.dstIp = ipToUint32(std::string(dstIP));
    payload.nextHopIp = ipToUint32("192.168.191.129");

    payload.snmpInIndex = 2;
    payload.snmpOutIndex = 3;
  } else {
    // IP from left side, but appears to come from right
    int leftHost = rand() % (254 - 130 + 1) + 130;
    char spoofIP[16];
    snprintf(spoofIP, sizeof(spoofIP), "192.168.191.%d", leftHost);
    payload.srcIp = ipToUint32(std::string(spoofIP));

    int rightHost = rand() % (126 - 2 + 1) + 2;
    char dstIP[16];
    snprintf(dstIP, sizeof(dstIP), "192.168.191.%d", rightHost);
    payload.dstIp = ipToUint32(std::string(dstIP));
    payload.nextHopIp = ipToUint32("192.168.191.1");

    payload.snmpInIndex = 3;
    payload.snmpOutIndex = 2;
  }

  payload.srcPort = static_cast<uint16_t>(rand() % 64512 + 1024);
  payload.dstPort = HTTP_PORT;

  fillCommonFields(payload, PAYLOAD_AVG_MD, 6, rand() % 32);
  return payload;
}

std::vector<NetflowPayload> createNetFlowPayload(int recordCount) {
  std::vector<NetflowPayload> payload(recordCount);

  for (int i = 0; i < recordCount; ++i) {
    if (rand() % 2 == 0)
      payload[i] = flowLtoR();
    else
      payload[i] = flowRtoL();
  }

  return payload;
}

Netflow generateNetflow(int recordCount) {
  Netflow data;
  NetflowHeader header = createNetFlowHeader(recordCount);
  std::vector<NetflowPayload> records = createNetFlowPayload(recordCount);

  data.header = header;
  data.records = records;

  return data;
}

std::string serializeNetFlowData(const Netflow &data) {
  size_t totalSize =
      sizeof(NetflowHeader) + data.records.size() * sizeof(NetflowPayload);
  std::string buffer;
  buffer.reserve(totalSize);

  NetflowHeader header = data.header;

  header.version = htons(header.version);
  header.flowCount = htons(header.flowCount);
  header.sysUptime = htonl(header.sysUptime);
  header.unixSec = htonl(header.unixSec);
  header.unixMsec = htonl(header.unixMsec);
  header.flowSequence = htonl(header.flowSequence);
  header.engineType = htons(header.engineType);
  header.engineId = htons(header.engineId);
  header.sampleInterval = htons(header.sampleInterval);

  buffer.append(reinterpret_cast<const char *>(&header), sizeof(header));

  for (const NetflowPayload &record : data.records) {
    NetflowPayload payload = record;

    payload.srcIp = htonl(payload.srcIp);
    payload.dstIp = htonl(payload.dstIp);
    payload.nextHopIp = htonl(payload.nextHopIp);
    payload.srcPort = htons(payload.srcPort);
    payload.dstPort = htons(payload.dstPort);
    payload.ipProtocol = payload.ipProtocol; // no need to convert naja
    payload.srcAsNumber = htons(payload.srcAsNumber);
    payload.dstAsNumber = htons(payload.dstAsNumber);
    payload.srcPrefixMask = htons(payload.srcPrefixMask);
    payload.dstPrefixMask = htons(payload.dstPrefixMask);
    payload.numPackets = htonl(payload.numPackets);
    payload.numOctets = htonl(payload.numOctets);
    payload.sysUptimeEnd = htonl(payload.sysUptimeEnd);
    payload.sysUptimeStart = htonl(payload.sysUptimeStart);
    payload.snmpInIndex = htons(payload.snmpInIndex);
    payload.snmpOutIndex = htons(payload.snmpOutIndex);
    payload.padding1 = 0;
    payload.padding2 = 0;
    payload.ipTos = 0;

    buffer.append(reinterpret_cast<const char *>(&payload), sizeof(payload));
  }

  return buffer;
}

NetflowPayload fillCommonFields(NetflowPayload &payload, int numPktOct,
                                int ipProtocol, int srcPrefixMask) {
  payload.numPackets = randomNum(10, 500); 
  payload.numOctets = randomNum(500, 15000);

  payload.padding1 = 0;
  payload.ipProtocol = static_cast<uint8_t>(ipProtocol);
  payload.ipTos = randomNum(0, 255);

  payload.srcAsNumber = randomNum(64000, 65000);
  payload.dstAsNumber = randomNum(64000, 65000);

  payload.srcPrefixMask = static_cast<uint8_t>(srcPrefixMask);
  payload.dstPrefixMask = 24;
  payload.padding2 = 0;

  int duration = randomNum(100, 10000);
  payload.sysUptimeStart = sysUptime - duration;
  payload.sysUptimeEnd = sysUptime;

  payload.tcpFlags = static_cast<uint8_t>(rand() % 16);

  return payload;
}
