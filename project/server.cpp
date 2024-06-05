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
#include <stdbool.h>
#include "utils.h"
#include <time.h>

using namespace std;
int seq_num = 1;
int ack_num = 0;
vector<Packet> send_packets_buff;
vector<bool> acked_packets;
int received_cum_ack = 0;
int highest_sent_packet = 0;
int send_base = 1;
bool cwnd_full = false;

// Global variables for the timer
time_t start_time;
double timeout_seconds = RTO;  // Set the timeout duration to 5 seconds
bool timer_on = false;

// Function to start the timer
void start_timer() {
    start_time = time(NULL);  // Record the current time
    timer_on = true;
}

// Function to check if the timer has expired
int timer_expired() {
    time_t current_time = time(NULL);
    double elapsed_seconds = difftime(current_time, start_time);
    return elapsed_seconds >= timeout_seconds;
}

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

    // don't move on until server gets a connection from client
    Packet received_pkt, send_pkt, dummy_pkt;
    send_packets_buff.push_back(dummy_pkt); // dummy packet to match sequence number

    int bytes_recvd = -1;
    while(bytes_recvd < 0)
      bytes_recvd = recvfrom(serv_sockfd, &received_pkt, sizeof(received_pkt), 0, (struct sockaddr*) &client_addr, &client_size);

    // Received packet must be data, not an ACK
    cout << "Received from client: ";
    cout.flush(); 
    write(STDOUT_FILENO, received_pkt.payload, received_pkt.payload_size);
    cout << endl;
    bytes_recvd = 0;

    // Create and send ACK packet, don't start timer for ACK
    ack_num = received_pkt.packet_number;
    create_packet(&send_pkt, 0, ack_num, "0", 1); // data set to "0" for an ACK
    sendto(serv_sockfd, &send_pkt, sizeof(send_pkt), 0, (struct sockaddr *) &client_addr, sizeof(client_addr));
    //================================================//
    //================================================//

    //define buffer for receiving packets from client
    Packet receive_buffer[2000];
    bool received[2000] = {false};

    //define packet expected number
    u_int32_t client_packet_expected = 1;

    while(true){
      // 1. Check if timer expired --> retransmit
      if(timer_on && timer_expired()){
        cout << "timer expired" << endl;
        // Retransmit lowest unACK'd packet to be sent
        Packet lowest_unACK_pkt = send_packets_buff.at(received_cum_ack + 1);
        cout << "resending: " << lowest_unACK_pkt.packet_number << endl;
        sendto(serv_sockfd, &lowest_unACK_pkt, sizeof(lowest_unACK_pkt), 0, (struct sockaddr *) &client_addr, sizeof(client_addr));
        start_timer();
        // continue;
      }

      // 2. Listen for data from clients
      int bytes_recvd = recvfrom(serv_sockfd, &received_pkt, sizeof(received_pkt), 0, (struct sockaddr*) &client_addr, &client_size);
      if (bytes_recvd > 0) {
        int received_pack_num = received_pkt.packet_number;

        //Case 1: Received packet is data
        if(received_pack_num != 0){
          cout << "Received from Client: ";
          cout.flush(); 
          write(STDOUT_FILENO, received_pkt.payload, received_pkt.payload_size);
          cout << endl;

          // Create and send ACK packet
          ack_num = received_pack_num; // TODO: CHANGE THIS TO CORRECT ACK NUM
          create_packet(&send_pkt, 0, ack_num, "0", 1); // data set to "0" for an ACK
          sendto(serv_sockfd, &send_pkt, sizeof(send_pkt), 0, (struct sockaddr *) &client_addr, sizeof(client_addr));
        }

        else{ // Case 2: Received packet is an ACK
          cout << "Received ACK from Client: " << received_pkt.ack_number << endl;

          // 1. reset timer
          start_timer();
          received_cum_ack = received_pkt.ack_number;

          // 2. Update cwnd bounds if necessary
          if(seq_num <= received_cum_ack + CWND_SIZE) // next available seq num <= last packet in upper bound
            cwnd_full = false;

          // 3. cancel timer if all packets were received
          if(received_cum_ack == send_packets_buff.size() - 1)
            timer_on = false;
        }
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
      
      //================================================//
      //================================================//
      // PART 2: STANDARD IN 
      char std_in_buffer [MSS];
      ssize_t bytes_read;
      while(!cwnd_full && (bytes_read = read(STDIN_FILENO, std_in_buffer, MSS))> 0){
        create_packet(&send_pkt, seq_num++, 0, (const char*) std_in_buffer, bytes_read);
        send_packets_buff.push_back(send_pkt); // store in case of retransmission
        sendto(serv_sockfd, &send_pkt, sizeof(send_pkt), 0, (struct sockaddr *) &client_addr, sizeof(client_addr));
        start_timer();

        // cout << "sending: " << send_pkt.payload << endl;
        // Check if congestion window is full now: seq_num now represents the next packet that needs to be sent
        // Transmission window: [smallest unACK'd packet, smallest unACK'd packet + 20)
        if(seq_num > received_cum_ack + CWND_SIZE){ // next seq num > last packet in cwnd 
          // cout << "=================" << endl;
          // cout << "cwnd is full now" << endl;
          // cout << "next avalable seq num = " << seq_num << ", upper packet bound = " << received_cum_ack + CWND_SIZE << endl;
          cwnd_full = true;  
        }
      } 
    }
    /* 8. You're done! Terminate the connection */     
    close(serv_sockfd);
    return 0; 
}