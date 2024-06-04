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

    // 1. Create a listening socket (UDP)
    int serv_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (serv_sockfd < 0) {
        cerr << "listening socket creation failed" << endl;
        exit(3);
    }
    // 3. Setup fd set for nonblock
    int flags = fcntl(serv_sockfd, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(serv_sockfd, F_SETFL, flags);

    int flags_stdin = fcntl(STDIN_FILENO, F_GETFL);
    flags_stdin |= O_NONBLOCK;
    fcntl(STDIN_FILENO, F_SETFL, flags_stdin);

    //4. Construct server address 
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(listening_port); 
    serv_addr.sin_addr.s_addr = INADDR_ANY; 
   
    /* 3. Let operating system know about our config */
    int listen_did_bind = bind(serv_sockfd, (struct sockaddr*) &serv_addr, 
                        sizeof(serv_addr));
    
    // Error if did_bind < 0 :(
    if (listen_did_bind < 0){
      cerr << "listening socket failed to bind" << endl;
      exit(3);
    } 

    // repeat for client
    struct sockaddr_in client_addr; // Same information, but about client
    memset(&client_addr, 0, sizeof(client_addr));
    socklen_t client_size = sizeof(client_addr);

    char client_buf[1024];

    // dont' move on until connection has been made
    int bytes_recvd = -1;
    while(bytes_recvd < 0)
      bytes_recvd = recvfrom(serv_sockfd, &client_buf, MSS, 0, (struct sockaddr*) &client_addr, &client_size);

    client_buf[bytes_recvd] = '\0';
    cout << "Received from client: " << client_buf << endl;
    bytes_recvd = 0;

    //define buffer for receiving packets from client
    Packet client_receive_buffer[2000];
    bool received[2000] = {false};
    //define packet expected number
    u_int32_t client_packet_expected = 1;

    Packet dummy_pkt;
    send_packets_buff.push_back(dummy_pkt);
    while(true){
      // /* 4. Create buffer to store incoming data */
      // // READ FROM CLIENT
      // bool client_sent_data = false;

      // Packet client_buf;
      char client_buf[1024];

      /* 5. Listen for data from clients */
      int bytes_recvd = recvfrom(serv_sockfd, &client_buf, MSS, 0, (struct sockaddr*) &client_addr, &client_size);
      if (bytes_recvd > 0) {
          client_buf[bytes_recvd] = '\0';
          cout << "Received from client: " << client_buf << endl;
          bytes_recvd = 0;
      }

      // // Execution will stop here until `BUF_SIZE` is read or termination/error
      // // bytes received is
      // if (bytes_recvd >= 0) 
      //   client_sent_data = true;

      // if(client_sent_data){
      //   // // casting received data to a packet
      //   // Packet* client_packet = reinterpret_cast<Packet*>(client_buf);
      //   //one packet received at a time
      //   //note: client_receive_buffer -- index + 1 should = packet #
      //   client_receive_buffer[client_buf.packet_number - 1] = client_buf;
      //   received[client_buf.packet_number - 1] = true;
      //   //check with expected packet #
      //   while (received[client_packet_expected - 1]){
      //     Packet pkt = client_receive_buffer[client_packet_expected - 1];
      //     printf("packet_number: %d, ack_number: %d, payload_size: %d, padding: %d,  payload: %s\n", 
      //     pkt.packet_number, pkt.ack_number, pkt.payload_size, pkt.padding, pkt.payload);

      //     client_packet_expected++;
      //   }

        
      //   // TODO: send an ACK back
      //   // add in packet
      //   /* 7. Send data back to client */
      //   char server_buf[] = "Hello world!";
      //   int did_send = sendto(send_sockfd, server_buf, strlen(server_buf), 
      //                     // socket  send data   how much to send
      //                         0, (struct sockaddr*) &client_addr, 
      //                     // flags   where to send
      //                         sizeof(client_addr));
      //   if (did_send < 0) {
      //       cerr << "failed to send data from server to client" << endl;
      //       exit(3);
      //     } 
      //     // TODO: send ACK back to client
      // }
      
      // PART 2: STANDARD IN 
      // If something happened on stdin, then we read the input
        
      // bool std_in_given = false;
      char std_in_buffer [MSS];
      struct Packet pkt;
      ssize_t bytes_read = read(STDIN_FILENO, std_in_buffer, MSS);
      if(bytes_read > 0){
        cout << "Server sending: " << endl;
        sendto(serv_sockfd, &std_in_buffer, sizeof(std_in_buffer), 0, (struct sockaddr *)&client_addr,  sizeof(client_addr));
        bytes_read = 0;
      }

      // while(bytes_read > 0){
      //   create_packet(&pkt, seq_num++, ack_num++, (const char*) std_in_buffer, bytes_read);
      //   // printf("Packet %d: Packet Number = %u, Payload Size = %u, Payload = %s...\n",
      //   //         seq_num, pkt.packet_number, pkt.payload_size, pkt.payload);
      //   send_packets_buff.push_back(pkt);
      //   bytes_read = read(STDIN_FILENO, std_in_buffer, MSS);
      // }
      // send_base = send_packets(send_packets_buff, send_base, send_sockfd, (struct sockaddr *)&serv_addr);
    } 

    /* 8. You're done! Terminate the connection */     
    close(serv_sockfd);
    return 0; 

}