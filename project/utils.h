#ifndef UTILS_H
#define UTILS_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

#define CWND_SIZE 20
#define MSS 1024
#define MAX_BUFFER_SIZE 2048000 //1024 * 2000

#define CLIENT_PORT 6002
#define CLIENT_LISTENING_PORT 5001
#define LOCAL_HOST "127.0.0.1"


using namespace std;

struct Packet {
    uint32_t packet_number;
    uint32_t ack_number;
    uint16_t payload_size;
    uint16_t padding;
    char payload[MSS]; // Maximum segment size
};

void create_packet(struct Packet* pkt, unsigned short seq_num, unsigned short ack_num, const char* payload_buff, unsigned int bytes_read){
    pkt->packet_number = seq_num;
    pkt->ack_number = ack_num; // This can be set to some relevant value
    pkt->payload_size = bytes_read; // either size 1024 or less
    pkt->padding = 0; // TODO: CHANGE TO CORRECT PADDING
    memcpy(&pkt->payload, payload_buff, bytes_read);
}

int send_packets(vector<Packet> send_buff, int send_base, int send_sockfd, const struct sockaddr *servaddr){
    int packets_left_to_send = send_buff.size() - send_base;
    int size = send_buff.size();
    int cwnd_limit = send_base + CWND_SIZE;
    int limit = min(cwnd_limit, size);

    for(int send_base = 0; send_base < limit; send_base++){
        Packet packet_to_send = send_buff.at(send_base);
        sendto(send_sockfd, (void *)& packet_to_send, sizeof(packet_to_send), 0, (struct sockaddr *)&servaddr,  sizeof(servaddr));
    }
    return send_base;
}


#endif