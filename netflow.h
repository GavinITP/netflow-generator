#ifndef NETFLOW_H
#define NETFLOW_H

#include <vector>
#include <sstream>
#include <cstdint>

struct NetflowHeader
{
    uint16_t version;
    uint16_t flowCount;
    uint32_t sysUptime;
    uint32_t unixSec;
    uint32_t unixMsec;
    uint32_t flowSequence;
    uint8_t engineType;
    uint8_t engineId;
    uint16_t sampleInterval;
};

struct NetflowPayload
{
    uint32_t srcIp;
    uint32_t dstIp;
    uint32_t nextHopIp;
    uint16_t snmpInIndex;
    uint16_t snmpOutIndex;
    uint32_t numPackets;
    uint32_t numOctets;
    uint32_t sysUptimeStart;
    uint32_t sysUptimeEnd;
    uint16_t srcPort;
    uint16_t dstPort;
    uint8_t padding1;
    uint8_t tcpFlags;
    uint8_t ipProtocol;
    uint8_t ipTos;
    uint16_t srcAsNumber;
    uint16_t dstAsNumber;
    uint8_t srcPrefixMask;
    uint8_t dstPrefixMask;
    uint16_t padding2;
};

struct Netflow
{
    NetflowHeader header;
    std::vector<NetflowPayload> records;
};

Netflow generateNetflow(int recordCount);
std::stringstream serializeNetFlowData(const Netflow &data);

#endif