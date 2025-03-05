#ifndef UTILS_H
#define UTILS_H

#include <cstdint>
#include <string>

int randomNum(int min, int max);
uint16_t genRandUint16(int max);
uint32_t genRandUint32(int max);
uint32_t ipToUint32(const std::string &ipStr);

#endif