#ifndef UTILS_H
#define UTILS_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <arpa/inet.h>
#include <stdint.h>

#define CWND_SIZE 20
#define MSS 1024
#define SECURITY_MSS 900
#define DATA_MESSAGE_MSS 1000
#define SECRET_SIZE 32
#define IV_SIZE 16
#define MAC_SIZE 32


#define CLIENT_PORT 6016
#define LOCAL_HOST "127.0.0.1"
#define RTO 1

using namespace std;

struct Packet {
    uint32_t packet_number;  // 32 is long
    uint32_t ack_number;
    uint16_t payload_size;  // 16 is short
    uint16_t padding;
    char payload[MSS]; // Maximum segment size
};

struct SecurityHeader {
    uint8_t  MsgType;  // 8 bits for MsgType
    uint8_t  Padding;  // 8 bits for Padding
    uint16_t MsgLen;   // 16 bits for MsgLen
};

struct Certificate {
    uint16_t KeyLength;
    uint16_t Padding;
    char PublicKey_Signature[]; // 70 - 72 bytes, always less than 255 but should be any
};

struct ClientHello {
    struct SecurityHeader Header;
    uint8_t CommType; // 8 bits for CommType, don't need to reorder because only a byte
    uint8_t Padding[3]; // 24 bits for Padding
    char ClientNonce[32]; // 32 Bytes for Client Nonce
};

struct ServerHello {
    struct SecurityHeader Header;
    uint8_t CommType;
    uint8_t SigSize;
    uint16_t CertSize;
    char ServerNonce[32]; // always exactly 32 bytes --> change to a *?
    char ServerCertificate_ClientNonceSignature[];
};

struct KeyExchangeRequest {
    struct SecurityHeader Header;
    uint8_t Padding;
    uint8_t SigSize;
    uint16_t CertSize;
    char ClientCertificate_ServerNonceSignature[];
};

struct DataMessage {
    struct SecurityHeader Header;
    uint16_t PayloadSize;
    uint16_t Padding;
    char IV[16];
    char payload[MSS - 20];
    uint8_t MACcode[32];
};

// void print_packet(struct Packet* pkt){
//     cout << "Packet Number: " << pkt->packet_number << endl;
//     cout << "Ack Number: " << pkt->ack_number << endl;
//     cout << "Payload Size: " << pkt->payload_size << endl;
//     cout << "Padding: " << pkt->padding << endl;
//     cout << "Payload: " ;
//     cout.flush();
//     write(STDOUT_FILENO, pkt->payload, pkt->payload_size);
//     cout << endl;
//     cout << endl;
// }

inline void create_packet(struct Packet* pkt, unsigned short seq_num, unsigned short ack_num, const char* payload_buff, unsigned int bytes_read){
    pkt->packet_number = htonl(seq_num);
    pkt->ack_number = htonl(ack_num); // This can be set to some relevant value
    pkt->payload_size = htons(bytes_read); // either size 1024 or less
    pkt->padding = htons(0); 
    memcpy(&pkt->payload, payload_buff, bytes_read);
}

inline void char_array_to_packet(char* buffer, struct Packet* pkt) {
    memcpy(pkt, buffer, sizeof(struct Packet));
}

inline void packet_to_char_array(struct Packet* pkt, char* buffer) {
    memcpy(buffer, pkt, sizeof(struct Packet));
}

#endif