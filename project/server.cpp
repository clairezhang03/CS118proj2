#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <cstdint>
#include <vector>
#include <stdbool.h>
#include "utils.h"
#include <time.h>
#include "security.h"

using namespace std;
uint32_t seq_num = 1;
uint32_t ack_num = 0;
vector<Packet> send_packets_buff;
int received_cum_ack = 0;
bool cwnd_full = false;
bool first_packet = false;

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
        cerr << "Usage: server <use_security> <port> <private_key_file> <certificate_file>" << endl;
        exit(3);
    }

    int use_security;
    int listening_port;
    char* private_key_file;
    char* certificate_file;
    try {
        use_security = stoi(argv[1]);
        listening_port = stoi(argv[2]);

        if(use_security){
          private_key_file = argv[3];
          certificate_file = argv[4];
        }
        
    } catch (const invalid_argument& e) {
        cerr << "Invalid argument for flag or port. Please provide valid integers." << endl;
        exit(3);
    } catch (const out_of_range& e) {
        cerr << "Argument out of range for flag or port. Please provide valid integers within range." << endl;
        exit(3);
    }

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

    //define buffer for receiving packets from client
    Packet receive_buffer[2003];
    bool received[2003] = {false};

    //define packet expected number
    uint32_t client_packet_expected = 1;
    cout << "here26" << endl;

    int bytes_recvd = -1;
    while(bytes_recvd < 0)
      bytes_recvd = recvfrom(serv_sockfd, &received_pkt, sizeof(received_pkt), 0, (struct sockaddr*) &client_addr, &client_size);

    //************************************************//
    //************************************************//
    // HANDLE SECURITY HANDSHAKE HERE

    uint8_t comm_type = 0;
    struct ClientHello* client_hello;
    char* client_nonce;

    if (use_security == 1){
      //received_pkt --> payload
      uint16_t payload_size = ntohs(received_pkt.payload_size);
      if (payload_size == sizeof(struct ClientHello)) {
          // Cast the payload to a ClientHello struct

          client_hello = (struct ClientHello*)received_pkt.payload;

          uint8_t msg_type = client_hello->Header.MsgType;
          if (msg_type != 1){
             cerr << "wrong message type received" << endl;
             exit(3);
          }
          printf("MsgType: %u\n", client_hello->Header.MsgType);
          printf("CommType: %u\n", client_hello->CommType);
          printf("ClientNonce: %.*s\n", 32, client_hello->ClientNonce);
          
      } else {
        cerr << "Payload size mismatch" << endl;
        exit(3);
      }
      //update expected for receive buffer
      client_packet_expected++;
      ack_num = client_packet_expected - 1;
      //set the comm_type as a flag
      comm_type = client_hello->CommType;
      client_nonce = client_hello->ClientNonce; //Check if &
      printf("here2 ");

      //constructing and sending a ServerHello
      struct ServerHello* server_hello;
      cout << sizeof(server_hello) << endl;
      load_certificate(certificate_file);
      load_private_key(private_key_file);
      derive_public_key();
      //size_t server_hello_size = create_server_hello(&server_hello, comm_type, client_nonce, certificate_file, private_key_file);

      uint16_t c_size = htons(cert_size);
      char signature[EVP_PKEY_size(ec_priv_key)];
      size_t sig_size;
      if (ec_priv_key != NULL){
          sig_size = sign(client_nonce, 32, signature);
          cout << "not exit early" << endl;
      }
      else{
          cout << "exit early" << endl;
          exit(3);
      }
      uint8_t s_size = sig_size;

      server_hello = (ServerHello*)::operator new(40 + cert_size + sig_size);
      char message[40 + cert_size + sig_size];

      struct SecurityHeader header;
      header.MsgType = 2;
      header.Padding = 0;
      header.MsgLen = htons(36 + sig_size + cert_size); //CHECK
      cout << sizeof(header) << endl;
      
      memcpy(message, &header, sizeof(header));

      cout << sizeof(comm_type) << endl;
      memcpy(message + sizeof(header), &comm_type, sizeof(comm_type));
      cout << sizeof(s_size) << endl;
      memcpy(message + sizeof(header) + sizeof(comm_type), &sig_size, sizeof(s_size));
      cout << sizeof(c_size) << endl;
      memcpy(message + sizeof(header) + sizeof(comm_type) + sizeof(s_size), &c_size, sizeof(c_size));

      char server_nonce[32];
      generate_nonce(server_nonce, 32);
      cout << sizeof(server_nonce) << endl;
      memcpy(message + sizeof(header) + sizeof(comm_type) + sizeof(s_size) + sizeof(c_size), &server_nonce, 32);

      cout << cert_size << endl;
      memcpy(message + sizeof(header) + sizeof(comm_type) + sizeof(s_size) + sizeof(c_size) + 32, certificate, cert_size);
      printHex(message, sizeof(message));
      cout << sig_size << endl;
      cout << s_size << endl;
      memcpy(message + sizeof(header) + sizeof(comm_type) + sizeof(s_size) + sizeof(c_size) + 32 + cert_size, &signature, sig_size);

      cout << sizeof(message) << endl;
      memcpy(server_hello, message, sizeof(message));

      printHex(signature, sig_size);


      cout << sizeof(server_hello) << endl;
      create_packet(&send_pkt, seq_num++, ack_num, (const char*)server_hello, sizeof(message));
      cout << "anything" << endl;
      sendto(serv_sockfd, &send_pkt, sizeof(send_pkt), 0, (struct sockaddr *) &client_addr, sizeof(client_addr));
      start_timer();

      bool waiting_key_exchange = true;
      bool creating_finish = false;

      struct KeyExchangeRequest* key_exchange;

      server_hello = (ServerHello*)::operator new(payload_size);

      while(true){ //CHANGE TO VARIABLE
        if (waiting_key_exchange){

          //retransmission
          if(timer_on && timer_expired()){
            //resend serverhello
            sendto(serv_sockfd, &send_pkt, sizeof(send_pkt), 0, (struct sockaddr *) &client_addr, sizeof(client_addr));
            start_timer();
          }

          bytes_recvd = recvfrom(serv_sockfd, &received_pkt, sizeof(received_pkt), 0, (struct sockaddr*) &client_addr, &client_size);
          if (bytes_recvd > 0) {
            //receive key exchange
            uint16_t payload_size = ntohs(received_pkt.payload_size);
            key_exchange = (KeyExchangeRequest*)::operator new(payload_size);

            memcpy(key_exchange, received_pkt.payload, payload_size);
            uint8_t msg_type = key_exchange->Header.MsgType;
            if (msg_type != 16){
              cerr << "wrong message type received" << endl;
              exit(3);
            }

            printf("MsgType: %u\n", key_exchange->Header.MsgType);
            waiting_key_exchange = false;
            creating_finish = true;
          }
        } else if (creating_finish){
          uint16_t cert_size_key_exchange = ntohs(key_exchange->CertSize);

          

        }
      }


    }



    first_packet = true;
    // Received packet must be data, not an ACK
    uint32_t received_pkt_number = ntohl(received_pkt.packet_number);
    if (received_pkt_number != 0) {
      receive_buffer[received_pkt_number] = received_pkt;
      received[received_pkt_number] = true;
    
      while (received[client_packet_expected]){
        Packet pkt = receive_buffer[client_packet_expected];
        // printf("packet_number: %d, ack_number: %d, payload_size: %d, padding: %d,  payload: %s\n", 
        // pkt.packet_number, pkt.ack_number, pkt.payload_size, pkt.padding, pkt.payload);
        // cout << "Received from Client: ";
        // cout.flush(); 
        write(STDOUT_FILENO, pkt.payload, ntohs(pkt.payload_size));
        client_packet_expected++;
      }

      // Create and send ACK packet, don't start timer for ACK
      ack_num = client_packet_expected - 1;
    }
    else {
      // cout << "Received ACK from Client: " << received_pkt.ack_number << endl;
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
    //================================================//
    //================================================//

    while(true){
      // 1. Check if timer expired --> retransmit
      if(timer_on && timer_expired()){
        // cout << "Timer expired" << endl;
        // Retransmit lowest unACK'd packet to be sent
        Packet lowest_unACK_pkt = send_packets_buff.at(received_cum_ack + 1);
        // cout << "Resending: " << lowest_unACK_pkt.packet_number << endl;
        sendto(serv_sockfd, &lowest_unACK_pkt, sizeof(lowest_unACK_pkt), 0, (struct sockaddr *) &client_addr, sizeof(client_addr));
        start_timer();
      }

      // 2. Listen for data from clients
      if (!first_packet){
        ack_num = 0;
        int bytes_recvd = recvfrom(serv_sockfd, &received_pkt, sizeof(received_pkt), 0, (struct sockaddr*) &client_addr, &client_size);
        if (bytes_recvd > 0) {
          uint32_t received_pack_num = ntohl(received_pkt.packet_number);
          uint32_t received_pack_ack = ntohl(received_pkt.ack_number);

          //Case 1: Received packet contains data
          if(received_pack_num != 0){
            //one packet received at a time
            receive_buffer[received_pack_num] = received_pkt;
            received[received_pack_num] = true;
            //check with expected packet #
            while (received[client_packet_expected]){
              Packet pkt = receive_buffer[client_packet_expected];
              // printf("packet_number: %d, ack_number: %d, payload_size: %d, padding: %d,  payload: %s\n", 
              // pkt.packet_number, pkt.ack_number, pkt.payload_size, pkt.padding, pkt.payload);
              // cout << "Received from Client: ";
              // cout.flush(); 
              write(STDOUT_FILENO, pkt.payload, ntohs(pkt.payload_size));
              // cout << endl;
              client_packet_expected++;
            }

            // Create and send ACK packet
            ack_num = client_packet_expected - 1;
          }

          if (received_pack_ack != 0) { // Case 2: Received packet is an ACK
            // cout << "Received ACK from Client: " << received_pkt.ack_number << endl;

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
      }
      first_packet = false;
      
      //================================================//
      //================================================//
      // PART 2: STANDARD IN 
      char std_in_buffer [MSS];
      ssize_t bytes_read;
      if (!cwnd_full && (bytes_read = read(STDIN_FILENO, std_in_buffer, MSS)) > 0) {
        create_packet(&send_pkt, seq_num++, ack_num, (const char*) std_in_buffer, bytes_read);
        send_packets_buff.push_back(send_pkt); // store in case of retransmission
        sendto(serv_sockfd, &send_pkt, sizeof(send_pkt), 0, (struct sockaddr *) &client_addr, sizeof(client_addr));
        start_timer();

        // cout << "Sending: " << send_pkt.payload << endl;
        // Check if congestion window is full now: seq_num now represents the next packet that needs to be sent
        // Transmission window: [smallest unACK'd packet, smallest unACK'd packet + 20)
        if(seq_num > received_cum_ack + CWND_SIZE){ // next seq num > last packet in cwnd 
          // cout << "=================" << endl;
          // cout << "cwnd is full now" << endl;
          // cout << "next avalable seq num = " << seq_num << ", upper packet bound = " << received_cum_ack + CWND_SIZE << endl;
          cwnd_full = true;  
        }
      }
      else if (ack_num != 0){
        // Pure ACK
        create_packet(&send_pkt, 0, ack_num, "0", 1); // data set to "0" for an ACK
        sendto(serv_sockfd, &send_pkt, sizeof(send_pkt), 0, (struct sockaddr *) &client_addr, sizeof(client_addr));
      }
    }
    /* 8. You're done! Terminate the connection */     
    close(serv_sockfd);
    return 0; 
}