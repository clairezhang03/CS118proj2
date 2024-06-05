#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <cstdint>
#include <vector>
#include "utils.h"
#include <time.h>
// #include "security.h"

using namespace std;
uint32_t seq_num = 1;
uint32_t ack_num = 0;
vector<Packet> send_packets_buff;
int send_base = 1;
int received_cum_ack = 0;
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
        cerr << "client <flag> <hostname> <port> <ca_public_key_file>" << endl;
        exit(3);
    }

    int flag;
    int server_listening_port;
    // int client_port;
    try {
        flag = stoi(argv[1]);
        server_listening_port = stoi(argv[3]);
        // client_port = stoi(argv[4]);
    } catch (const invalid_argument& e) {
        cerr << "Invalid argument for flag or port. Please provide valid integers." << endl;
        exit(3);
    } catch (const out_of_range& e) {
        cerr << "Argument out of range for flag or port. Please provide valid integers within range." << endl;
        exit(3);
    }

    // if(hostname == "localhost")
    //   hostname = LOCAL_HOST;
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


    const char* hostname = argv[2];
    if (strcmp(hostname, "localhost") == 0) 
      hostname = LOCAL_HOST;

    // 2. Construct server address
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET; // use IPv4
    serv_addr.sin_port = htons(server_listening_port); 
    serv_addr.sin_addr.s_addr = inet_addr(hostname); 
    socklen_t server_size = sizeof(serv_addr);

    struct sockaddr_in client_addr;
    client_addr.sin_family = AF_INET; 
    // client_addr.sin_port = htons(CLIENT_PORT); // 69 nice
    client_addr.sin_addr.s_addr = INADDR_ANY; 
   
    // 3. Bind socket to a port 
    int did_bind = bind(client_sockfd, (struct sockaddr*) &client_addr, 
                        sizeof(client_addr));
    
    // Error if did_bind < 0 :(
    if (did_bind < 0){
      cerr << "Client: socket failed to bind" << endl;
      exit(3);
    } 

     // don't move on until server gets a connection from client
    Packet received_pkt, send_pkt, dummy_pkt;
    send_packets_buff.push_back(dummy_pkt); // dummy packet to match sequence number

    //================================================//
    //================================================//

    //define buffer for receiving packets from client
    Packet client_receive_buffer[2001];
    bool received[2001] = {false};

    //define packet expected number
    uint32_t client_packet_expected = 1;

    while(true){
      // 1. Check if timer expired --> retransmit
      if(timer_on && timer_expired()){
        // cout << "timer expired" << endl;
        // Retransmit lowest unACK'd packet to be sent
        Packet lowest_unACK_pkt = send_packets_buff.at(received_cum_ack + 1);
        // cout << "resending: " << lowest_unACK_pkt.packet_number << endl;
        sendto(client_sockfd, &lowest_unACK_pkt, sizeof(lowest_unACK_pkt), 0, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
        start_timer();
        // continue;
      }

      // 2. Listen for data from clients
      ack_num = 0;
      int bytes_recvd = recvfrom(client_sockfd, &received_pkt, sizeof(received_pkt), 0, (struct sockaddr*) &serv_addr, &server_size);
      if (bytes_recvd > 0) {
        uint32_t received_pack_num = ntohl(received_pkt.packet_number);
        uint32_t received_pack_ack = ntohl(received_pkt.ack_number);

        //Case 1: Received packet is data
        if(received_pack_num != 0){
          // cout << "Received from Server: ";
          // cout.flush(); 
          // write(STDOUT_FILENO, received_pkt.payload, received_pkt.payload_size);
          // cout << endl;

          //one packet received at a time
          //note: client_receive_buffer -- index + 1 should = packet #
          client_receive_buffer[received_pack_num] = received_pkt;
          received[received_pack_num] = true;
          //check with expected packet #
          while (received[client_packet_expected]){
            Packet pkt = client_receive_buffer[client_packet_expected];
            // printf("packet_number: %d, ack_number: %d, payload_size: %d, padding: %d,  payload: %s\n", 
            // pkt.packet_number, pkt.ack_number, pkt.payload_size, pkt.padding, pkt.payload);
            // cout << "Received from Server: ";
            // cout.flush(); 
            write(STDOUT_FILENO, pkt.payload, ntohs(pkt.payload_size));
            // cout << endl;

            client_packet_expected++;
          }

          // Create and send ACK packet
          ack_num = client_packet_expected - 1; // TODO: CHANGE THIS TO CORRECT ACK NUM
          // create_packet(&send_pkt, 0, ack_num, "0", 1); // data set to "0" for an ACK
          // sendto(client_sockfd, &send_pkt, sizeof(send_pkt), 0, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
        }

        if (received_pack_ack != 0){ // Case 2: Received packet is an ACK
          // cout << "Received ACK from Server: " << received_pkt.ack_number << endl;

          // 1. reset timer
          start_timer();
          received_cum_ack = ntohl(received_pkt.ack_number);

          // 2. Update cwnd bounds if necessary
          if(seq_num <= received_cum_ack + CWND_SIZE) // next available seq num <= last packet in upper bound
            cwnd_full = false;

          // 3. cancel timer if all packets were received
          if(received_cum_ack == send_packets_buff.size() - 1)
            timer_on = false;
        }
      }

      //================================================//
      //================================================//
      // PART 2: STANDARD IN 
      
      // int temp = 0;
      char std_in_buffer [MSS];
      ssize_t bytes_read;
      if (!cwnd_full && (bytes_read = read(STDIN_FILENO, std_in_buffer, MSS)) > 0) {
      //   if (temp == 1){
          // create_packet(&send_pkt, 3, 0, (const char*) std_in_buffer, bytes_read);
      //   }
      //   else{
      //     create_packet(&send_pkt, seq_num++, 0, (const char*) std_in_buffer, bytes_read);
      //     if (temp == 2){
      //       seq_num++;
      //     }
      //   }
      //   temp++;

        create_packet(&send_pkt, seq_num++, ack_num, (const char*) std_in_buffer, bytes_read);
        send_packets_buff.push_back(send_pkt); // store in case of retransmission
        sendto(client_sockfd, &send_pkt, sizeof(send_pkt), 0, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
        start_timer();
        // cout << "sus" << endl;

        //cout << "sending: " << send_pkt.payload << endl;
        // Check if congestion window is full now: seq_num now represents the next packet that needs to be sent
        // Transmission window: [smallest unACK'd packet, smallest unACK'd packet + 20)
        if(seq_num > received_cum_ack + CWND_SIZE){ // next seq num > last packet in cwnd 
          // cout << "=================" << endl;
          // cout << "cwnd is full now" << endl;
          // cout << "next avalable seq num = " << seq_num << ", upper packet bound = " << received_cum_ack + CWND_SIZE << endl;
          cwnd_full = true;  
        }
      } 
      else if(ack_num != 0){
        // Pure ACK
        create_packet(&send_pkt, 0, ack_num, "0", 1); // data set to "0" for an ACK
        sendto(client_sockfd, &send_pkt, sizeof(send_pkt), 0, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
      }
    }
    /* 8. You're done! Terminate the connection */     
    close(client_sockfd);
    return 0; 
}