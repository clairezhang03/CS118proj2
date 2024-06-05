#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread>

void error(const char* msg) {
    perror(msg);
    exit(1);
}

void receiveData(int sockfd) {
    char buffer[1024];
    while (true) {
        memset(buffer, 0, 1024);
        ssize_t n = recvfrom(sockfd, buffer, 1024, 0, NULL, NULL);
        if (n < 0) {
            error("ERROR on recvfrom");
        } else {
            std::cout << "Received: " << std::string(buffer, n) << std::endl;
        }
    }
}

void sendData(int sockfd, struct sockaddr_in serv_addr) {
    std::string input;
    char buffer[1024];
    while (getline(std::cin, input)) {
        strcpy(buffer, input.c_str());
        ssize_t n = sendto(sockfd, buffer, strlen(buffer), 0, (const struct sockaddr *)&serv_addr, sizeof(serv_addr));
        if (n < 0) {
            error("ERROR on sendto");
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0] << " <hostname> <port> <ca_public_key_file> <flag>\n";
        exit(1);
    }

    int sockfd;
    struct sockaddr_in serv_addr;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");

    struct sockaddr_in serv_addr;
    memset((char *) &serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(atoi(argv[2]));

    if (inet_aton(argv[1], &serv_addr.sin_addr) == 0) {
        fprintf(stderr, "ERROR, no such host\n");
        std::cerr << "ERROR, no such host\n";
        exit(0);
    }

    char buffer[1024];
    while (true) {
        std::string data;
        std::getline(std::cin, data); // Read data from stdin
        strcpy(buffer, data.c_str());
        ssize_t n = sendto(sockfd, buffer, data.length(), 0, (const struct sockaddr *)&serv_addr, sizeof(serv_addr));
        if (n < 0) error("ERROR on sendto");
    }
    std::thread receiver(receiveData, sockfd);
    std::thread sender(sendData, sockfd, serv_addr);

    receiver.join();
    sender.join();

    close(sockfd);
    return 0;
  47 changes: 32 additions & 15 deletions47  
project/server.cpp
Original file line number	Diff line number	Diff line change
@@ -4,13 +4,36 @@
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread>

void error(const char* msg) {
    perror(msg);
    exit(1);
}

void receiveData(int sockfd, struct sockaddr_in &cli_addr, socklen_t &clilen) {
    char buffer[1024];
    while (true) {
        memset(buffer, 0, 1024);
        ssize_t n = recvfrom(sockfd, buffer, 1024, 0, (struct sockaddr *)&cli_addr, &clilen);
        if (n < 0) {
            error("ERROR on recvfrom");
        } else {
            std::cout.write(buffer, n);
            std::cout << std::endl;
        }
    }
}

void sendData(int sockfd, struct sockaddr_in &cli_addr, socklen_t &clilen) {
    std::string input;
    char buffer[1024];
    while (getline(std::cin, input)) {
        strcpy(buffer, input.c_str());
        sendto(sockfd, buffer, strlen(buffer), 0, (struct sockaddr *)&cli_addr, clilen);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <port> <private_key_file> <certificate_file>\n";
@@ -19,30 +42,24 @@ int main(int argc, char* argv[]) {

    int sockfd;
    struct sockaddr_in serv_addr, cli_addr;
    socklen_t clilen;
    char buffer[1024];
    socklen_t clilen = sizeof(cli_addr);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");
    if (sockfd < 0) error("ERROR opening socket");

    memset((char *) &serv_addr, 0, sizeof(serv_addr));
    int portno = atoi(argv[1]);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);
    serv_addr.sin_port = htons(atoi(argv[1]));

    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) 
        error("ERROR on binding");

    clilen = sizeof(cli_addr);
    while (true) {
        memset(buffer, 0, 1024);
        ssize_t n = recvfrom(sockfd, buffer, 1024, 0, (struct sockaddr *)&cli_addr, &clilen);
        if (n < 0) error("ERROR on recvfrom");
        std::cout.write(buffer, n); // Output received data directly to stdout
        std::cout.flush();
    }
    std::thread receiver(receiveData, sockfd, std::ref(cli_addr), std::ref(clilen));
    std::thread sender(sendData, sockfd, std::ref(cli_addr), std::ref(clilen));

    receiver.join();
    sender.join();

    close(sockfd);
    return 0;