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
    int listening_port = stoi(argv[2]);
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
    servaddr.sin_port = htons(listening_port); // set receiving port, Big endian
    servaddr.sin_addr.s_addr = INADDR_ANY; // accept all connections, // same as inet_addr("0.0.0.0") // "Address string to network bytes"
   
    /* 3. Let operating system know about our config */
    int listen_did_bind = bind(listen_sockfd, (struct sockaddr*) &servaddr, 
                        sizeof(servaddr));
    
    // Error if did_bind < 0 :(
    if (listen_did_bind < 0){
      cerr << "listening socket failed to bind" << endl;
      exit(3);
    } 

    // repeat for client
    struct sockaddr_in clientaddr; // Same information, but about client
    socklen_t clientsize = sizeof(clientaddr);
    
    int did_find_client = listen(listen_sockfd, 1);
                          // socket  flags

    // Error if did_find_client < 0 :(
    if (did_find_client < 0){
      cerr << "could not find client" << endl;
      exit(3);
    } 

    int clientfd = accept(listen_sockfd, (struct sockaddr*) &clientaddr, &clientsize);
    // Error if clientfd < 0 :(
    if (clientfd < 0){
      cerr << "could not accept client" << endl;
      exit(3);
    } 
     
     /* 6. Inspect data from client */
    char* client_ip = inet_ntoa(clientaddr.sin_addr); // "Network bytes to address string"
    int client_port = ntohs(clientaddr.sin_port); // Little endian

    //define buffer for receiving packets from client
    Packet client_receive_buffer[2000];
    bool received[2000] = {false};
    //define packet expected number
    u_int32_t client_packet_expected = 1;


    Packet dummy_pkt;
    send_packets_buff.push_back(dummy_pkt);
    while(true){
      /* 4. Create buffer to store incoming data */
      // READ FROM CLIENT
      bool client_sent_data = false;

      Packet client_buf;
      struct sockaddr_in clientaddr; // Same information, but about client
      socklen_t clientsize = sizeof(clientaddr);

      /* 5. Listen for data from clients */
      int bytes_recvd = recvfrom(sockfd, &client_buf, MSS, 
                              // socket  store data  how much
                                0, (struct sockaddr*) &clientaddr, 
                                &clientsize);

      // Execution will stop here until `BUF_SIZE` is read or termination/error
      // bytes received is
      if (bytes_recvd >= 0) 
        client_sent_data = true;

      if(client_sent_data){
        // // casting received data to a packet
        // Packet* client_packet = reinterpret_cast<Packet*>(client_buf);
        //one packet received at a time
        //note: client_receive_buffer -- index + 1 should = packet #
        client_receive_buffer[client_buf.packet_number - 1] = client_buf;
        received[client_buf.packet_number - 1] = true;
        //check with expected packet #
        while (received[client_packet_expected - 1]){
          Packet pkt = client_receive_buffer[client_packet_expected - 1];
          printf("packet_number: %d, ack_number: %d, payload_size: %d, padding: %d,  payload: %s\n", 
          pkt.packet_number, pkt.ack_number, pkt.payload_size, pkt.padding, pkt.payload);

          client_packet_expected++;
        }

        
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
        
      // bool std_in_given = false;
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
      send_base = send_packets(send_packets_buff, send_base, send_sockfd, (struct sockaddr *)&servaddr);
    } 

    /* 8. You're done! Terminate the connection */     
    close(listen_sockfd);
    return 0; 

}