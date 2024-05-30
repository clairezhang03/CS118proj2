#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <iostream>
#include <fcntl.h>
#include <cstdint>

using namespace std;

#define MSS = 1024; 
#define MAX_BUFFER_SIZE = 2048000; //1024 * 2000

struct Packet {
    uint32_t packet_number;
    uint32_t ack_number;
    uint16_t payload_size;
    uint16_t padding;
    char payload[1024]; // Maximum segment size
};

void create_packet(std::vector<Packet> &packets, uint32_t packet_number, uint32_t ack_number, const char *payload) {
    Packet packet;
    packet.packet_number = htonl(packet_number);
    packet.ack_number = htonl(ack_number);
    packet.payload_size = htons(1024);
    std::memcpy(packet.payload, payload, 1024);
    packets.push_back(packet);
}

int main(int argc, char *argv[]) {
  // does not have proper formatting for error
    if (argc < 5) { 
        cerr << "Usage: server <flag> <port> <private_key_file> <certificate_file>" << endl;
        exit(3);
    }

    int flag = stoi(argv[1]);
    int port = stoi(argv[2]);
    const char* private_key_file = argv[3];
    const char* certificate_file = argv[4];
    
    /* 1. Create socket */
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
                     // use IPv4  use UDP

    if (sockfd < 0) {
        cerr << "socket creation failed" << endl;
        exit(3);
    }

    // Setup fd set for nonblock
    int flags = fcntl(sockfd, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(sockfd, F_SETFL, flags);

    int flags_stdin = fcntl(STDIN_FILENO, F_GETFL);
    flags_stdin |= O_NONBLOCK;
    fcntl(STDIN_FILENO, F_SETFL, flags_stdin);

    /* 2. Construct our address */
    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET; // use IPv4
    servaddr.sin_addr.s_addr = INADDR_ANY; // accept all connections, // same as inet_addr("0.0.0.0") // "Address string to network bytes"
    servaddr.sin_port = htons(port); // set receiving port, Big endian

    /* 3. Let operating system know about our config */
    int did_bind = bind(sockfd, (struct sockaddr*) &servaddr, 
                        sizeof(servaddr));
    
    // Error if did_bind < 0 :(
    if (did_bind < 0){
      cerr << "socket failed to bind" << endl;
      exit(3);
    } 

    while(true){
      /* 4. Create buffer to store incoming data */
      // READ FROM CLIENT
      bool client_sent_data = false;

      int BUF_SIZE = 1024;
      char client_buf[BUF_SIZE];
      struct sockaddr_in clientaddr; // Same information, but about client
      socklen_t clientsize = sizeof(clientaddr);

      /* 5. Listen for data from clients */
      int bytes_recvd = recvfrom(sockfd, client_buf, BUF_SIZE, 
                              // socket  store data  how much
                                0, (struct sockaddr*) &clientaddr, 
                                &clientsize);

      // Execution will stop here until `BUF_SIZE` is read or termination/error
      // bytes received is
      if (bytes_recvd >= 0) 
        client_sent_data = true;

      if(client_sent_data){
        // add in packet stuff
        // TODO: reorder the packets and write out message
        cout << "Message: " << client_buf << endl;

         /* 6. Inspect data from client */
        char* client_ip = inet_ntoa(clientaddr.sin_addr); // "Network bytes to address string"
        int client_port = ntohs(clientaddr.sin_port); // Little endian

        // TODO: send an ACK back
        // add in packet
        /* 7. Send data back to client */
        char server_buf[] = "Hello world!";
        int did_send = sendto(sockfd, server_buf, strlen(server_buf), 
                          // socket  send data   how much to send
                              0, (struct sockaddr*) &clientaddr, 
                          // flags   where to send
                              sizeof(clientaddr));
        if (did_send < 0) {
            cerr << "failed to send data from server to client" << endl;
            exit(3);
          } 
          // TODO: send ACK back to client
      }
      
      
      // PART 2: STANDARD IN 
        // If something happened on stdin, then we read the input
        bool std_in_given = false;

        char std_in_buffer[MAX_BUFFER_SIZE];
        if (read(STDIN_FILENO, std_in_buffer, MAX_BUFFER_SIZE) >= 0){
          std_in_given = true;
        }

        if(std_in_given){
           // create packet and send to client
          /* 6. Inspect data from client */
          char* client_ip = inet_ntoa(clientaddr.sin_addr); // "Network bytes to address string"
          int client_port = ntohs(clientaddr.sin_port); // Little endian

          // add in packet
          /* 7. Send data back to client */
          char server_buf[] = "Hello world!";
          int did_send = sendto(sockfd, server_buf, strlen(server_buf), 
                            // socket  send data   how much to send
                                0, (struct sockaddr*) &clientaddr, 
                            // flags   where to send
                                sizeof(clientaddr));
          if (did_send < 0) {
              cerr << "failed to send data from server to client" << endl;
              exit(3);
          }
        }         
         /* 8. You're done! Terminate the connection */     
    close(sockfd);
    return 0; 
    }

      
  }
  