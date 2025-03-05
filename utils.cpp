#include "utils.h"

#include <random>
#include <arpa/inet.h>

int randomNum(int min, int max)
{
    return min + (rand() % (max - min + 1));
}

uint16_t genRandUint16(int max)
{
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(0, max);

    return static_cast<uint16_t>(dis(gen));
}

uint32_t genRandUint32(int max)
{
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(0, max);

    return static_cast<uint32_t>(dis(gen));
}

uint32_t ipToUint32(const std::string &ipStr)
{
    struct in_addr ip;
    inet_pton(AF_INET, ipStr.c_str(), &ip);

    return ntohl(ip.s_addr);
}
