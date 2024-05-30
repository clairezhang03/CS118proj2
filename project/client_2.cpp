#include <iostream>
#include <cstring>
#include <csignal>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define BUFFER_SIZE 1024

int sockfd;
struct sockaddr_in serv_addr;

void error(const char *msg) {
    perror(msg);
    exit(1);
}

void handle_sigint(int signum) {
    close(sockfd);
    std::cerr << "Client terminated gracefully" << std::endl;
    exit(0);
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0] << " <flag> <hostname> <port> <ca_public_key_file>" << std::endl;
        exit(1);
    }

    int flag = atoi(argv[1]);
    const char* hostname = argv[2];
    int port = atoi(argv[3]);
    const char* ca_public_key_file = argv[4];

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        error("ERROR opening socket");
    }

    struct hostent *server = gethostbyname(hostname);
    if (server == NULL) {
        std::cerr << "ERROR, no such host" << std::endl;
        exit(1);
    }

    memset((char *)&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(port);

    signal(SIGINT, handle_sigint);

    if (flag == 1) {
        // Perform the security handshake here (simplified example)
        std::cerr << "Performing security handshake" << std::endl;
        // If the handshake fails or times out
        // exit(3);
    }

    char buffer[BUFFER_SIZE];
    while (true) {
        std::cin.read(buffer, BUFFER_SIZE);
        std::streamsize bytesRead = std::cin.gcount();

        if (bytesRead > 0) {
            int n = sendto(sockfd, buffer, bytesRead, 0, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
            if (n < 0) {
                error("ERROR in sendto");
            }

            // Receive acknowledgment from the server
            char ackBuffer[BUFFER_SIZE];
            n = recvfrom(sockfd, ackBuffer, BUFFER_SIZE, 0, NULL, NULL);
            if (n < 0) {
                error("ERROR in recvfrom");
            }

            // Print the acknowledgment
            std::cout.write(ackBuffer, n);
            std::cout.flush();
        }

        // Check if we have reached the end of stdin
        if (std::cin.eof()) {
            break;
        }
    }

    close(sockfd);
    return 0;
}

Client^