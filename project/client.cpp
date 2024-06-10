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
#include "security.h"

using namespace std;
uint32_t seq_num = 1;
uint32_t ack_num = 0;
vector<Packet> send_packets_buff;
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
        cerr << "client <use_security> <hostname> <port> <ca_public_key_file>" << endl;
        exit(3);
    }

    int use_security;
    const char* hostname;
    int server_listening_port;
    char* ca_public_key_file;
    try {
        use_security = stoi(argv[1]);
        hostname = argv[2];
        if (strcmp(hostname, "localhost") == 0) 
          hostname = LOCAL_HOST;
        server_listening_port = stoi(argv[3]);

        if(use_security){ // public key file passed in if security is used
          ca_public_key_file = argv[4];
        }
    } catch (const invalid_argument& e) {
        cerr << "Invalid argument for flag or port. Please provide valid integers." << endl;
        exit(3);
    } catch (const out_of_range& e) {
        cerr << "Argument out of range for flag or port. Please provide valid integers within range." << endl;
        exit(3);
    }

   

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

    // 2. Construct server address
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET; // use IPv4
    serv_addr.sin_port = htons(server_listening_port); 
    serv_addr.sin_addr.s_addr = inet_addr(hostname); 
    socklen_t server_size = sizeof(serv_addr);

    struct sockaddr_in client_addr;
    client_addr.sin_family = AF_INET; 
    client_addr.sin_addr.s_addr = INADDR_ANY; 
   
    // 3. Bind socket to a port 
    int did_bind = bind(client_sockfd, (struct sockaddr*) &client_addr, 
                        sizeof(client_addr));
    
    // Error if did_bind < 0 :(
    if (did_bind < 0){
      cerr << "Client: socket failed to bind" << endl;
      exit(3);
    }


    //************************************************//
    //************************************************//

     // don't move on until server gets a connection from client
    Packet received_pkt, send_pkt, dummy_pkt;
    send_packets_buff.push_back(dummy_pkt); // dummy packet to match sequence number

    //define buffer for receiving packets from client
    Packet client_receive_buffer[2003];
    bool received[2003] = {false};

    //define packet expected number
    uint32_t client_packet_expected = 1;


    //************************************************//
    //************************************************//
    // HANDLE SECURITY HANDSHAKE HERE
    if (use_security == 1){
      generate_private_key();

      derive_public_key();
      cout << "pub" << endl;


      struct ClientHello client_hello;
      create_client_hello(&client_hello, 1);

      create_packet(&send_pkt, seq_num++, ack_num, (const char*)&client_hello, sizeof(client_hello));
      sendto(client_sockfd, &send_pkt, sizeof(send_pkt), 0, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
      start_timer();

      bool waiting_server_hello = true;
      bool create_key_exchange = false;

      struct ServerHello* server_hello;

      while(true){ //CHANGE TO VARIABLE
      
        if (waiting_server_hello){

          //retransmission
          if(timer_on && timer_expired()){
            //resend clienthello
            sendto(client_sockfd, &send_pkt, sizeof(send_pkt), 0, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
            start_timer();
            //check if we need to worry about send_packets_buff -- update this if we do
          }

          int bytes_recvd = recvfrom(client_sockfd, &received_pkt, sizeof(received_pkt), 0, (struct sockaddr*) &serv_addr, &server_size);
          if (bytes_recvd > 0) {
            //receive server hello

            uint16_t payload_size = ntohs(received_pkt.payload_size);
            if (payload_size >= sizeof(struct ServerHello)) {
                // Cast the payload to a ServerHello struct
                server_hello = (ServerHello*)::operator new(payload_size);
                cout << sizeof(server_hello) << endl;
                cout << payload_size << endl;
                memcpy(server_hello, received_pkt.payload, payload_size);

                // char server_hello_msg[payload_size];
                // memcpy(server_hello_msg, server_hello, payload_size);

                // printHex(server_hello_msg, payload_size);

                // Access the fields of server_hello
                printf("MsgType: %u\n", server_hello->Header.MsgType);
                // printf("CommType: %u\n", server_hello->CommType);
                printf("SigSize: %u\n", server_hello->SigSize);
                // printf("CertSize: %u\n", ntohs(server_hello->CertSize));
                // printf("ServerNonce: %.*s\n", 32, server_hello->ServerNonce);
                // Assuming the Certificate structure has a printable field, e.g., data
                //printf("ServerCertificate: %.*s\n", sizeof(server_hello->ServerCertificate), server_hello->ServerCertificate);
                //printf("ClientNonceSignature: %.*s\n", sizeof(server_hello->ClientNonceSignature), server_hello->ClientNonceSignature);
            } else {
                cerr << "Payload size mismatch or insufficient data" << endl; 
                exit(3);
            }
            client_packet_expected++;
            ack_num = client_packet_expected - 1;
            waiting_server_hello = false;
            create_key_exchange = true;
          }
        } else if (create_key_exchange){
          uint16_t cert_size = ntohs(server_hello->CertSize);
          uint16_t sig_size = server_hello->SigSize;
          // char cert_and_sig[cert_size + sig_size] = server_hello->ServerCertificate_ClientNonceSignature;
          char cert[cert_size];
          char client_nonce_sig[sig_size];

          char* cert_sig_data = server_hello->ServerCertificate_ClientNonceSignature;

          memcpy(&cert, cert_sig_data, cert_size);
          cout <<"cert" << endl;
          memcpy(&client_nonce_sig, cert_sig_data + cert_size, sig_size);
          cout <<"client nonce sig" << endl;

          char* cert_data = cert;

          struct Certificate* cert_nonce = (Certificate*)::operator new(cert_size);
          // parse_certificate(cert_data, &cert_nonce, cert_size);
        
          memcpy(cert_nonce, cert_data, cert_size);
          cout << "parse cert" << endl;



          uint16_t key_length = ntohs(cert_nonce->KeyLength);
          //cout << key_length << endl;
          char cert_sig[cert_size - 4 - key_length];
          // cout << cert_nonce->PublicKey_Signature << endl;
          char* cert_nonce_pub_key_sig = cert_nonce->PublicKey_Signature;
          memcpy(cert_sig, cert_nonce_pub_key_sig + key_length, cert_size - 4 - key_length);
          cout << "cert_sig" << endl;

          char cert_pub_key[key_length];
          memcpy(cert_pub_key, cert_nonce_pub_key_sig, key_length);
          cout << "cert public key" << endl;

          char* cert_pub_key_data = cert_pub_key;
          cout << "pubkey" << endl;
          printHex(cert_pub_key, key_length);
          char* sig_data = cert_sig;
          cout << "cert sig" << endl;
          printHex(cert_sig, cert_size - 4 - key_length);

          load_ca_public_key(ca_public_key_file);
          // int ret = call_verify_cert(cert_pub_key_data, key_length, sig_data, key_length);
          int ret = verify(cert_pub_key_data, key_length, sig_data, cert_size - 4 - key_length, ec_ca_public_key);
          cout << "verify cert" << endl;
          if (ret != 1){
            cout << "please no" << endl;
            cerr << "server signature not verified" << endl;
            exit(3);
          }
          load_peer_public_key(cert_pub_key, key_length);

          char* client_nonce_sig_data = client_nonce_sig;
          int ret_nonce = call_verify_nonce(client_hello.ClientNonce, 32, client_nonce_sig_data, server_hello->SigSize);
          cout << "verify nonce" << endl;
          if (ret_nonce != 1){
            cerr << "client nonce not verified" << endl;
            exit(3);
          }
          cout << "verified and good" << endl;

          derive_secret();

          if (server_hello->CommType ==  1){
            derive_keys();
          }

          //create keyexchange request

          //sign the client's public key
          char client_cert_signature[255]; //am i ALLOCATING the CORRECT SIZE?
          size_t client_cert_sig_size = sign(public_key, pub_key_size, client_cert_signature);
          cout << "client cert signed" << endl;

          uint16_t zero = 0;

          struct Certificate* client_cert = (Certificate*)::operator new(4 + pub_key_size + client_cert_sig_size);
          char client_cert_message[4 + pub_key_size + client_cert_sig_size];

          memcpy(client_cert_message, &pub_key_size, sizeof(uint16_t));

          memcpy(client_cert_message + sizeof(uint16_t), &zero, sizeof(uint16_t));

          // char pub_key_no_ptr = &public_key;
          memcpy(client_cert_message + sizeof(uint16_t) + sizeof(uint16_t), public_key, pub_key_size);

          memcpy(client_cert_message + sizeof(uint16_t) + sizeof(uint16_t) + pub_key_size, &client_cert_signature, client_cert_sig_size);
          //client_cert created here
          memcpy(client_cert, client_cert_message, sizeof(client_cert_message));

          char* server_nonce = server_hello->ServerNonce;
          char signature[255];
          size_t sig_size_nonce;
          if (ec_priv_key != NULL){
              sig_size_nonce = sign(server_nonce, 32, signature);
              cout << "not exit early" << endl;
          }
          else{
              cerr << "exit early" << endl;
              exit(3);
          }

          uint8_t s_size = sig_size_nonce;

          struct KeyExchangeRequest* key_exchange = (KeyExchangeRequest*)::operator new(8 + sizeof(client_cert_message) + sig_size);
          char message[8 + sizeof(client_cert_message) + sig_size];

          struct SecurityHeader header;
          header.MsgType = 16;
          header.Padding = 0;
          header.MsgLen = htons(4 + sizeof(client_cert_message) + sig_size); //CHECK?

          memcpy(message, &header, sizeof(header));

          uint8_t zero_8 = 0;
          memcpy(message + sizeof(header), &zero_8, sizeof(uint8_t));

          memcpy(message + sizeof(header) + sizeof(uint8_t), &sig_size, sizeof(s_size));

          size_t client_cert_message_size = sizeof(client_cert_message);
          memcpy(message + sizeof(header) + sizeof(uint8_t) + sizeof(s_size), &client_cert_message_size, sizeof(uint16_t)); //CHECK

          memcpy(message + sizeof(header) + sizeof(uint8_t) + sizeof(s_size) + sizeof(uint16_t), &client_cert_message, sizeof(client_cert_message));

          memcpy(message + sizeof(header) + sizeof(uint8_t) + sizeof(s_size) + sizeof(uint16_t) + sizeof(client_cert_message), &signature, sig_size_nonce);

          memcpy(key_exchange, message, sizeof(message));
          cout << "MOM WE MADE IT" << endl;

          create_packet(&send_pkt, seq_num++, ack_num, (const char*)key_exchange, sizeof(message));
          sendto(client_sockfd, &send_pkt, sizeof(send_pkt), 0, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
          start_timer();

          create_key_exchange = false;
        }
      }

    }

    //================================================//
    //================================================//

    while(true){
      // 1. Check if timer expired --> retransmit
      if(timer_on && timer_expired()){
        // cout << "timer expired" << endl;
        // Retransmit lowest unACK'd packet to be sent
        Packet lowest_unACK_pkt = send_packets_buff.at(received_cum_ack + 1);
        // cout << "resending: " << lowest_unACK_pkt.packet_number << endl;
        sendto(client_sockfd, &lowest_unACK_pkt, sizeof(lowest_unACK_pkt), 0, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
        start_timer();
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
          ack_num = client_packet_expected - 1;
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

        create_packet(&send_pkt, seq_num++, ack_num, (const char*) std_in_buffer, bytes_read);
        send_packets_buff.push_back(send_pkt); // store in case of retransmission
        sendto(client_sockfd, &send_pkt, sizeof(send_pkt), 0, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
        start_timer();
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