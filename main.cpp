#include "netflow.h"

#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <thread>

#define SERVER_IP "192.168.120.58"
#define SERVER_PORT 9995
#define THREAD_COUNT 4

void sendNetFlowData()
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("Socket creation failed");
        return;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &serverAddr.sin_addr);

    int recordCount = 64; 
    Netflow netflowData = generateNetflow(recordCount);
    std::stringstream serializedData = serializeNetFlowData(netflowData);
    std::string serializedStr = serializedData.str();

    while (true)
    {
        sendto(sock, serializedStr.c_str(), serializedStr.size(), 0,
               (struct sockaddr *)&serverAddr, sizeof(serverAddr));
    }

    close(sock);
}

int main()
{
    std::vector<std::thread> threads;
    
    for (int i = 0; i < THREAD_COUNT; i++)
    {
        threads.emplace_back(sendNetFlowData);
    }

    for (auto &t : threads)
    {
        t.join();
    }

    return 0;
}