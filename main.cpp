#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 9995

int main()
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("Socket creation failed");
        return 1;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &serverAddr.sin_addr);

    const char *message = "Hello, UDP Server!";

    while (true)
    {
        ssize_t sentBytes = sendto(sock, message, strlen(message), 0,
                                   (struct sockaddr *)&serverAddr, sizeof(serverAddr));
        if (sentBytes < 0)
        {
            perror("Send failed");
        }
        else
        {
            std::cout << "Message sent: " << message << std::endl;
        }

        usleep(1000000); // microsecs
    }

    close(sock);
    return 0;
}