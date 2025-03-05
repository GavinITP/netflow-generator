#include "netflow.h"
#include "utils.h"

#include <chrono>
#include <vector>
#include <cstdint>
#include <cstdlib>
#include <arpa/inet.h>
#include <sstream>
#include <iostream>

enum Port
{
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

enum PayloadSize
{
    PAYLOAD_AVG_MD = 1024,
    PAYLOAD_AVG_SM = 256
};

long long startTime = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
uint32_t sysUptime = 0;
uint32_t flowSequence = 0;

NetflowHeader createNetFlowHeader(int recordCount)
{
    auto now = std::chrono::steady_clock::now();
    auto duration = now.time_since_epoch();
    long long t = std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count();

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

std::vector<NetflowPayload> createNetFlowPayload(int recordCount)
{
    std::vector<NetflowPayload> payload(recordCount);
    for (int i = 0; i < recordCount; i++)
    {
        switch (i % 16)
        {
        case 0:
            payload[i] = createHttpFlow();
            break;
        case 1:
            payload[i] = createHttpsFlow();
            break;
        case 2:
            payload[i] = createHttpAltFlow();
            break;
        case 3:
            payload[i] = createDnsFlow();
            break;
        case 4:
            payload[i] = createIcmpFlow();
            break;
        case 5:
            payload[i] = createNtpFlow();
            break;
        case 6:
            payload[i] = createImapsFlow();
            break;
        case 7:
            payload[i] = createMySqlFlow();
            break;
        case 8:
            payload[i] = createRandomFlow();
            break;
        case 9:
            payload[i] = createSshFlow();
            break;
        case 10:
            payload[i] = createP2pFlow();
            break;
        case 11:
            payload[i] = createBitorrentFlow();
            break;
        case 12:
            payload[i] = createFtpFlow();
            break;
        case 13:
            payload[i] = createSnmpFlow();
            break;
        case 14:
            payload[i] = createIcmpFlow();
            break;
        case 15:
            payload[i] = createRandomFlow();
            break;
        }
    }
    return payload;
}

Netflow generateNetflow(int recordCount)
{
    Netflow data;
    NetflowHeader header = createNetFlowHeader(recordCount);
    std::vector<NetflowPayload> records = createNetFlowPayload(recordCount);

    data.header = header;
    data.records = records;

    return data;
}

std::stringstream serializeNetFlowPayload(const Netflow &data)
{
    std::stringstream buffer;
    // Write the header (in Big Endian format)
    if (!buffer.write(reinterpret_cast<const char *>(&data.header), sizeof(data.header)))
    {
        std::cerr << "Writing netflow header failed." << std::endl;
    }
    // Write each record (in Big Endian format)
    for (const auto &record : data.records)
    {
        if (!buffer.write(reinterpret_cast<const char *>(&record), sizeof(record)))
        {
            std::cerr << "Writing netflow record failed." << std::endl;
        }
    }

    return buffer;
}

NetflowPayload createHttpFlow()
{
    NetflowPayload payload;
    payload.srcIp = ipToUint32("112.10.20.10");
    payload.dstIp = ipToUint32("172.30.190.10");
    payload.nextHopIp = ipToUint32("172.199.15.1");
    payload.srcPort = static_cast<uint16_t>(40);
    payload.dstPort = static_cast<uint16_t>(HTTP_PORT);

    fillCommonFields(payload, PAYLOAD_AVG_MD, 6, rand() % 32);

    return payload;
}

NetflowPayload createHttpsFlow()
{
    NetflowPayload payload;
    payload.srcIp = ipToUint32("192.168.20.10");
    payload.dstIp = ipToUint32("202.12.190.10");
    payload.nextHopIp = ipToUint32("172.199.15.1");
    payload.srcPort = static_cast<uint16_t>(40);
    payload.dstPort = static_cast<uint16_t>(HTTPS_PORT);

    fillCommonFields(payload, PAYLOAD_AVG_MD, 6, rand() % 32);

    return payload;
}

NetflowPayload createHttpAltFlow()
{
    NetflowPayload payload;

    payload.srcIp = ipToUint32("10.10.20.122");
    payload.dstIp = ipToUint32("84.12.190.210");
    payload.nextHopIp = ipToUint32("192.199.15.1");
    payload.srcPort = static_cast<uint16_t>(12001);
    payload.dstPort = static_cast<uint16_t>(HTTPS_ALT_PORT);
    payload.snmpInIndex = static_cast<uint16_t>(rand() % 2);

    fillCommonFields(payload, PAYLOAD_AVG_MD, 6, rand() % 32);

    return payload;
}

NetflowPayload createDnsFlow()
{
    NetflowPayload payload;

    payload.srcIp = ipToUint32("59.220.158.122");
    payload.dstIp = ipToUint32("10.12.233.210");
    payload.nextHopIp = ipToUint32("39.199.15.1");
    payload.srcPort = static_cast<uint16_t>(9221);
    payload.dstPort = static_cast<uint16_t>(DNS_PORT);
    payload.snmpInIndex = static_cast<uint16_t>(rand() % 2);

    fillCommonFields(payload, PAYLOAD_AVG_MD, 17, rand() % 32);

    return payload;
}

NetflowPayload createIcmpFlow()
{
    NetflowPayload payload;

    payload.srcIp = ipToUint32("172.16.50.10");
    payload.dstIp = ipToUint32("132.12.130.10");
    payload.nextHopIp = ipToUint32("132.12.130.1");
    payload.srcPort = 0;
    payload.dstPort = 0;
    payload.snmpInIndex = static_cast<uint16_t>(rand() % 2);

    fillCommonFields(payload, 0, 1, rand() % 32);

    return payload;
}

NetflowPayload createNtpFlow()
{
    NetflowPayload payload;

    payload.srcIp = ipToUint32("247.104.20.202");
    payload.dstIp = ipToUint32("10.12.190.10");
    payload.nextHopIp = ipToUint32("192.199.15.1");
    payload.srcPort = static_cast<uint16_t>(40);
    payload.dstPort = static_cast<uint16_t>(NTP_PORT);
    payload.snmpInIndex = static_cast<uint16_t>(rand() % 2);

    fillCommonFields(payload, PAYLOAD_AVG_MD, 17, 32);

    return payload;
}

NetflowPayload createImapsFlow()
{
    NetflowPayload payload;

    payload.srcIp = ipToUint32("172.30.20.102");
    payload.dstIp = ipToUint32("62.12.190.10");
    payload.nextHopIp = ipToUint32("131.199.15.1");
    payload.srcPort = static_cast<uint16_t>(9010);
    payload.dstPort = static_cast<uint16_t>(IMAPS_PORT);
    payload.snmpInIndex = static_cast<uint16_t>(rand() % 2);

    fillCommonFields(payload, PAYLOAD_AVG_MD, 6, rand() % 32);

    return payload;
}

NetflowPayload createMySqlFlow()
{
    NetflowPayload payload;

    payload.srcIp = ipToUint32("10.154.20.12");
    payload.dstIp = ipToUint32("77.12.190.94");
    payload.nextHopIp = ipToUint32("150.20.145.1");
    payload.srcPort = static_cast<uint16_t>(9010);
    payload.dstPort = static_cast<uint16_t>(MYSQL_PORT);
    payload.snmpInIndex = static_cast<uint16_t>(rand() % 2);

    fillCommonFields(payload, PAYLOAD_AVG_MD, 6, rand() % 32);

    return payload;
}

NetflowPayload createSshFlow()
{
    NetflowPayload payload;

    payload.srcIp = ipToUint32("172.30.20.102");
    payload.dstIp = ipToUint32("222.12.190.10");
    payload.nextHopIp = ipToUint32("192.199.15.1");
    payload.srcPort = static_cast<uint16_t>(40);
    payload.dstPort = static_cast<uint16_t>(SSH_PORT);
    payload.snmpInIndex = static_cast<uint16_t>(rand() % 2);

    fillCommonFields(payload, PAYLOAD_AVG_MD, 6, rand() % 32);

    return payload;
}

NetflowPayload createP2pFlow()
{
    NetflowPayload payload;

    payload.srcIp = ipToUint32("247.104.20.202");
    payload.dstIp = ipToUint32("10.12.190.10");
    payload.nextHopIp = ipToUint32("192.199.15.1");
    payload.srcPort = static_cast<uint16_t>(40);
    payload.dstPort = static_cast<uint16_t>(P2P_PORT);
    payload.snmpInIndex = static_cast<uint16_t>(rand() % 2);

    fillCommonFields(payload, PAYLOAD_AVG_MD, 17, 32);

    return payload;
}

NetflowPayload createBitorrentFlow()
{
    NetflowPayload payload;

    payload.srcIp = ipToUint32("192.168.20.202");
    payload.dstIp = ipToUint32("42.12.190.10");
    payload.nextHopIp = ipToUint32("192.199.15.1");
    payload.srcPort = static_cast<uint16_t>(40);
    payload.dstPort = static_cast<uint16_t>(BITTORRENT_PORT);
    payload.snmpInIndex = static_cast<uint16_t>(rand() % 2);

    fillCommonFields(payload, PAYLOAD_AVG_MD, 17, 32);

    return payload;
}

NetflowPayload createFtpFlow()
{
    NetflowPayload payload;

    payload.srcIp = ipToUint32("112.10.100.10");
    payload.dstIp = ipToUint32("192.168.120.10");
    payload.nextHopIp = ipToUint32("172.199.15.1");
    payload.srcPort = static_cast<uint16_t>(40);
    payload.dstPort = static_cast<uint16_t>(FTP_PORT);
    payload.snmpInIndex = static_cast<uint16_t>(rand() % 2);

    fillCommonFields(payload, PAYLOAD_AVG_MD, 6, rand() % 32);

    return payload;
}

NetflowPayload createSnmpFlow()
{
    NetflowPayload payload;

    payload.srcIp = ipToUint32("112.10.20.10");
    payload.dstIp = ipToUint32("172.30.190.10");
    payload.nextHopIp = ipToUint32("172.199.15.1");
    payload.srcPort = static_cast<uint16_t>(40);
    payload.dstPort = static_cast<uint16_t>(SNMP_PORT);
    payload.snmpInIndex = static_cast<uint16_t>(rand() % 2);

    fillCommonFields(payload, PAYLOAD_AVG_MD, 17, rand() % 32);

    return payload;
}

NetflowPayload createRandomFlow()
{
    NetflowPayload payload;

    payload.srcIp = rand();
    payload.dstIp = rand();
    payload.nextHopIp = rand();
    payload.srcPort = genRandUint16(UINT16_MAX);
    payload.dstPort = genRandUint16(UINT16_MAX);
    payload.snmpInIndex = static_cast<uint16_t>(rand() % 2);

    fillCommonFields(payload, PAYLOAD_AVG_MD, 6, rand() % 32);

    return payload;
}

NetflowPayload fillCommonFields(
    NetflowPayload &payload,
    int numPktOct,
    int ipProtocol,
    int srcPrefixMask)
{
    payload.snmpInIndex = static_cast<uint16_t>(rand() % 2);
    payload.snmpOutIndex = 0;
    payload.numPackets = genRandUint32(numPktOct);
    payload.numOctets = genRandUint32(numPktOct);
    payload.padding1 = 0;
    payload.ipProtocol = static_cast<uint8_t>(ipProtocol);
    payload.ipTos = 0;
    payload.srcAsNumber = genRandUint16(UINT16_MAX);
    payload.dstAsNumber = genRandUint16(UINT16_MAX);
    payload.srcPrefixMask = static_cast<uint8_t>(srcPrefixMask);
    payload.dstPrefixMask = static_cast<uint8_t>(rand() % 32);
    payload.padding2 = 0;

    int uptime = static_cast<int>(sysUptime);
    payload.sysUptimeEnd = static_cast<uint32_t>(uptime - randomNum(10, 500));
    payload.sysUptimeStart = payload.sysUptimeEnd - static_cast<uint32_t>(randomNum(10, 500));

    return payload;
}
