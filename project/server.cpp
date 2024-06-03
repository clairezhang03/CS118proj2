#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <iostream>
#include <fcntl.h>
#include <cstdint>
#include <vector>
#include "utils.h"

using namespace std;
int seq_num = 1;
int ack_num = 1;
vector<Packet> send_packets_buff;
int send_base = 0;

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
    int listen_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
                     // use IPv4  use UDP

    if (listen_sockfd < 0) {
        cerr << "listening socket creation failed" << endl;
        exit(3);
    }

    // Create a UDP socket for sending
    int send_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (send_sockfd < 0) {
        cerr << "sending socket creation failed" << endl;
        exit(3);
    }

    // socket for sending

    // Setup fd set for nonblock
    int flags = fcntl(listen_sockfd, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(listen_sockfd, F_SETFL, flags);

    int flags_stdin = fcntl(STDIN_FILENO, F_GETFL);
    flags_stdin |= O_NONBLOCK;
    fcntl(STDIN_FILENO, F_SETFL, flags_stdin);

    /* 2. Construct our address */
    // Construct address for sending data
    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET; // use IPv4
    servaddr.sin_port = htons(port); // set receiving port, Big endian
    servaddr.sin_addr.s_addr = INADDR_ANY; // accept all connections, // same as inet_addr("0.0.0.0") // "Address string to network bytes"
   
    /* 3. Let operating system know about our config */
    int did_bind = bind(listen_sockfd, (struct sockaddr*) &servaddr, 
                        sizeof(servaddr));
    
    // Error if did_bind < 0 :(
    if (did_bind < 0){
      cerr << "listening socket failed to bind" << endl;
      exit(3);
    } 

    // repeat for client
    struct sockaddr_in clientaddr;
    clientaddr.sin_family = AF_INET; // use IPv4
    clientaddr.sin_port = htons(CLIENT_PORT_FROM_SERVER); // set receiving port, Big endian
    clientaddr.sin_addr.s_addr = INADDR_ANY; // accept all connections, // same as inet_addr("0.0.0.0") // "Address string to network bytes"

    Packet dummy_pkt;
    send_packets_buff.push_back(dummy_pkt);
    while(true){
      // PART 2: STANDARD IN 
      // If something happened on stdin, then we read the input
        
      // bool std_in_given = false;
      bool last_packet = false;
      char std_in_buffer [MSS];
      struct Packet pkt;
      ssize_t bytes_read = read(STDIN_FILENO, std_in_buffer, MSS);
      while(bytes_read > 0){
        create_packet(&pkt, seq_num++, ack_num++, (const char*) std_in_buffer, bytes_read);
        // printf("Packet %d: Packet Number = %u, Payload Size = %u, Payload = %s...\n",
        //         seq_num, pkt.packet_number, pkt.payload_size, pkt.payload);
        send_packets_buff.push_back(pkt);
        bytes_read = read(STDIN_FILENO, std_in_buffer, MSS);
      }
      send_packets();
    } 

    /* 8. You're done! Terminate the connection */     
    close(listen_sockfd);
    return 0; 

}