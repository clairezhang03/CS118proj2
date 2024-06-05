#ifndef UTILS_H
#define UTILS_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

#define CWND_SIZE 20
#define MSS 1024
// #define MAX_BUFFER_SIZE 2048000 //1024 * 2000

#define CLIENT_PORT 6016
#define LOCAL_HOST "127.0.0.1"
#define RTO 1

using namespace std;

struct Packet {
    uint32_t packet_number;
    uint32_t ack_number;
    uint16_t payload_size;
    uint16_t padding;
    char payload[MSS]; // Maximum segment size
};

void print_packet(struct Packet* pkt){
    cout << "Packet Number: " << pkt->packet_number << endl;
    cout << "Ack Number: " << pkt->ack_number << endl;
    cout << "Payload Size: " << pkt->payload_size << endl;
    cout << "Padding: " << pkt->padding << endl;
    cout << "Payload: " ;
    cout.flush();
    write(STDOUT_FILENO, pkt->payload, pkt->payload_size);
    cout << endl;
    cout << endl;
}

void create_packet(struct Packet* pkt, unsigned short seq_num, unsigned short ack_num, const char* payload_buff, unsigned int bytes_read){
    pkt->packet_number = seq_num;
    pkt->ack_number = ack_num; // This can be set to some relevant value
    pkt->payload_size = bytes_read; // either size 1024 or less
    pkt->padding = 0; 
    memcpy(&pkt->payload, payload_buff, bytes_read);
}

void char_array_to_packet(char* buffer, struct Packet* pkt) {
    memcpy(pkt, buffer, sizeof(struct Packet));
}

void packet_to_char_array(struct Packet* pkt, char* buffer) {
    memcpy(buffer, pkt, sizeof(struct Packet));
}



#endif