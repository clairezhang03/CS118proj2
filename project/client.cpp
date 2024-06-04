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
int send_base = 1;

int main(int argc, char *argv[]) {
    // does not have proper formatting for error
    if (argc < 5) { 
        cerr << "client <flag> <hostname> <port> <ca_public_key_file>" << endl;
        exit(3);
    }

    int flag = stoi(argv[1]);
    const char* hostname = argv[2];
    int server_listening_port = stoi(argv[3]);
    int client_port = stoi(argv[4]);
    // const char* ca_public_key_file = argv[4]; // change back!!

   
    // 1. Create socket 
    int client_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (client_sockfd < 0) {
        cerr << "listening socket creation failed" << endl;
        exit(3);
    }

    // Setup listen_sockfd for non-blocking mode
    int flags = fcntl(client_sockfd, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(client_sockfd, F_SETFL, flags);

    // Setup stdin for non-blocking mode
    int flags_stdin = fcntl(STDIN_FILENO, F_GETFL);
    flags_stdin |= O_NONBLOCK;
    fcntl(STDIN_FILENO, F_SETFL, flags_stdin);

    // 2. Constructu server address
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET; // use IPv4
    serv_addr.sin_port = htons(server_listening_port); 
    serv_addr.sin_addr.s_addr = inet_addr(hostname); 
    socklen_t server_size = sizeof(serv_addr);

    struct sockaddr_in client_addr;
    client_addr.sin_family = AF_INET; 
    client_addr.sin_port = htons(client_port); 
    client_addr.sin_addr.s_addr = INADDR_ANY; 
   
    // 3. Bind socket to a port 
    int did_bind = bind(client_sockfd, (struct sockaddr*) &client_addr, 
                        sizeof(client_addr));
    
    // Error if did_bind < 0 :(
    if (did_bind < 0){
      cerr << "Client: socket failed to bind" << endl;
      exit(3);
    } 

    //================================================//
    //================================================//

    //define buffer for receiving packets from client
    Packet client_receive_buffer[2000];
    bool received[2000] = {false};
    //define packet expected number
    u_int32_t client_packet_expected = 1;

    // Place a dummy packet so sequence number does not start with 0
    Packet dummy_pkt;
    send_packets_buff.push_back(dummy_pkt);
    while(true){
      /* 4. Create buffer to store incoming data */
      // READ FROM CLIENT
      Packet client_buf;
      /* 5. Listen for data from clients */
      int bytes_recvd = recvfrom(client_sockfd, &client_buf, sizeof(client_buf), 0, (struct sockaddr*) &serv_addr, &server_size);
      if (bytes_recvd > 0) {
          cout << "Received from server: ";
          cout.flush(); 
          write(STDOUT_FILENO, client_buf.payload, client_buf.payload_size);
          cout << endl;
          bytes_recvd = 0;
      }
      
        // // casting received data to a packet
        // Packet* client_packet = reinterpret_cast<Packet*>(client_buf);
        //one packet received at a time
        //note: client_receive_buffer -- index + 1 should = packet #
        // client_receive_buffer[client_buf.packet_number - 1] = client_buf;
        // received[client_buf.packet_number - 1] = true;
        //check with expected packet #
        // while (received[client_packet_expected - 1]){
        //   Packet pkt = client_receive_buffer[client_packet_expected - 1];
        //   printf("packet_number: %d, ack_number: %d, payload_size: %d, padding: %d,  payload: %s\n", 
        //   pkt.packet_number, pkt.ack_number, pkt.payload_size, pkt.padding, pkt.payload);

        //   client_packet_expected++;

           // TODO: send an ACK back
          // add in packet
          /* 7. Send data back to client */
          // char server_buf[] = "Hello world!";
          // int did_send = sendto(send_sockfd, server_buf, strlen(server_buf), 
          //                   // socket  send data   how much to send
          //                       0, (struct sockaddr*) &client_addr, 
          //                   // flags   where to send
          //                       &sizeof(client_addr));
          // if (did_send < 0) {
          //     cerr << "failed to send data from server to client" << endl;
          //     exit(3);
          //   } 
            // TODO: send ACK back to client
      
       
      //================================================//
      //================================================//
      // PART 2: STANDARD IN 
      char std_in_buffer [MSS];
      struct Packet send_pkt;
      ssize_t bytes_read;
      while((bytes_read = read(STDIN_FILENO, std_in_buffer, MSS))> 0){
        create_packet(&send_pkt, seq_num++, ack_num++, (const char*) std_in_buffer, bytes_read);
        send_packets_buff.push_back(send_pkt);
      }

      // send packets
      /*
      Example: 0 1 2 3 4 5
      - size = 6
      - send_base = 2
      - 4 packets left to send: 2, 3, 4, 5
      - cwnd_limit_upper_bound = 2 + 20 = 22 --> sends [2, 22) = 20
      */

      int buffer_size = send_packets_buff.size(); 
      int cwnd_upper_bound = send_base + CWND_SIZE;
      int limit = min(cwnd_upper_bound, buffer_size);
      
      for(; send_base < limit; send_base++){
          Packet packet_to_send = send_packets_buff.at(send_base);
          // print_packet(&packet_to_send);
          sendto(client_sockfd, &send_packets_buff.at(send_base), sizeof(packet_to_send), 0, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
      }
    } 

    /* 8. You're done! Terminate the connection */     
    close(client_sockfd);
    return 0; 


}