#include <chrono>
#include <vector>
#include <cstdint>

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

long long startTime = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
uint32_t sysUptime = 0;
uint32_t flowSequence = 0;

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
    uint32_t srcIP;
    uint32_t dstIP;
    uint32_t nextHopIP;
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