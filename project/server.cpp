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

using namespace std;

#define MSS 1024
#define MAX_BUFFER_SIZE 2048000 //1024 * 2000

struct Packet {
    uint32_t packet_number;
    uint32_t ack_number;
    uint16_t payload_size;
    uint16_t padding;
    char* payload; // Maximum segment size
};

int next_available_seq_num = 1;
int next_ack_number = 0;
vector<Packet*> send_packets_buff;
int send_base = 0;

//Dane code:
  //CHANGED-- anything he changed from other's code
  //CHANGE-- things that might be wrong

void create_packets(char *std_in_buffer, int length){
    /*
    Formula Breakdown
      - length is an exact multiple of MSS, adding MSS - 1 does not change the number of chunks
      - When there is a remainder, adding MSS - 1 
          makes the integer division result increase by 1
           accounting for the partial chunk.
    */

    int num_chunks = (length + MSS - 1) / MSS;
    cout << "Number of chunks = " << num_chunks;

    for (int i = 0; i < num_chunks; i++) {
        char *payload_buff = new char[MSS]; 
        int start = i * MSS;
        int end = start + MSS;

        // Ensure we do not read beyond the buffer's length
        if (end > length) 
            end = length;

        int payload_buff_length = end - start;
        cout << "start = " << start << ", end = " << end << ", payload_buff length = " << payload_buff_length << endl;
        memcpy(payload_buff, std_in_buffer + start, payload_buff_length);

        // create a new packet
        struct Packet* pkt = new Packet;
        pkt->packet_number = next_available_seq_num++;
        pkt->ack_number = next_ack_number; // This can be set to some relevant value
        pkt->payload_size = payload_buff_length; // either size 1024 or less
        pkt->padding = 0; // TODO: CHANGE TO CORRECT PADDING
        pkt->payload = payload_buff;

        send_packets_buff.push_back(pkt);
         
        printf("Packet %d: Packet Number = %u, Payload Size = %u, Payload = %s...\n",
               i + 1, pkt->packet_number, pkt->payload_size, pkt->payload);
    }
}

void send_packets(int sockfd, const struct sockaddr_in clientaddr, const socklen_t clientsize){
  int send_end = send_base + 20; // end of packet buffer
  int send_packet_buff_size = send_packets_buff.size(); // highest_packet_num + 1

  int limit = send_packet_buff_size < send_end ? send_packet_buff_size : send_end;
  for(; send_base < limit; send_base++){
    int packet_size = send_packets_buff[send_base] -> payload_size;

    // send packet to client
    int did_send = sendto(sockfd, static_cast <void *> (send_packets_buff[send_base]), packet_size, 
                        // socket  send data   how much to send
                            0, (struct sockaddr*) &clientaddr, 
                          // flags   where to send
                            sizeof(clientaddr));
    if (did_send < 0) {
      cerr << "failed to send data from server to client" << endl;
      exit(3);
    } 
  }
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

    //define buffer for receiving packets from client
    vector<Packet*> client_receive_buffer;
    //define packet expected number
    u_int32_t client_packet_expected = 1;

    while(true){
      /* 4. Create buffer to store incoming data */
      // READ FROM CLIENT
      bool client_sent_data = false;

      char client_buf[MSS];
      struct sockaddr_in clientaddr; // Same information, but about client
      socklen_t clientsize = sizeof(clientaddr);

      /* 5. Listen for data from clients */
      int bytes_recvd = recvfrom(sockfd, client_buf, MSS, 
                              // socket  store data  how much
                                0, (struct sockaddr*) &clientaddr, 
                                &clientsize);

      // Execution will stop here until `BUF_SIZE` is read or termination/error
      // bytes received is
      if (bytes_recvd >= 0) 
        client_sent_data = true;

      if(client_sent_data){
        // casting received data to a packet
        Packet* client_packet = reinterpret_cast<Packet*>(client_buf);
        //one packet received at a time
        client_receive_buffer.push_back(client_packet);

        //check if it's in order
        //note: client_receive_buffer -- index + 1 should = packet #
        u_int32_t client_packet_temp = client_packet->packet_number;
        //check with expected packet #
        if (client_packet_temp != client_packet_expected){
          //TODO: Error protocol?
        }
        client_packet_expected++;

        // TODO: reorder the packets and write out message
        cout << "Message: " << &client_buf << endl;

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
      char* std_in_buffer = new char[MAX_BUFFER_SIZE];

      int bytes_read = read(STDIN_FILENO, std_in_buffer, MAX_BUFFER_SIZE);
      if (bytes_read >= 0)
        std_in_given = true;

      if(std_in_given){
        // create packet and send to client
        // std::cout.write(std_in_buffer, bytes_read) << endl;
        create_packets(std_in_buffer, bytes_read);
        send_packets(sockfd, clientaddr, clientsize);
      }        
    } 
     /* 8. You're done! Terminate the connection */     
    close(sockfd);
    return 0; 
  }
  