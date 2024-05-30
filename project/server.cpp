#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <iostream>

using namespace std;

int main(int argc, char *argv[]) {
  // does not have proper formatting for error
    if (argc != 3) {
        cerr << "Usage: server <port> <private_key_file> <certificate_file>" << endl;
        exit(3);
    }

    int port = stoi(argv[1]);
    const char* private_key_file = argv[2];
    const char* certificate_file = argv[3];
    
    /* 1. Create socket */
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
                     // use IPv4  use UDP

    if (sockfd < 0) {
        cerr << "socket creation failed" << endl;
        exit(3);
    }

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

    while(true){
      /* 4. Create buffer to store incoming data */
      int BUF_SIZE = 1024;
      char client_buf[BUF_SIZE];
      struct sockaddr_in clientaddr; // Same information, but about client
      socklen_t clientsize = sizeof(clientaddr);

      /* 5. Listen for data from clients */
      int bytes_recvd = recvfrom(sockfd, client_buf, BUF_SIZE, 
                              // socket  store data  how much
                                0, (struct sockaddr*) &clientaddr, 
                                &clientsize);
      // Execution will stop here until `BUF_SIZE` is read or termination/error
      // Error if bytes_recvd < 0 :(
      if (bytes_recvd < 0) {
        cerr << "failed to read buffer" << endl;
        exit(3);
      } 
      
      cout << "Message: " << client_buf << endl;

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

}




    
    

    
    /* 6. Inspect data from client */
    char* client_ip = inet_ntoa(clientaddr.sin_addr);
                    // "Network bytes to address string"
    int client_port = ntohs(clientaddr.sin_port); // Little endian
    // Print out data
    write(1, client_buf, bytes_recvd);

    /* 7. Send data back to client */
    char server_buf[] = "Hello world!";
    int did_send = sendto(sockfd, server_buf, strlen(server_buf), 
                       // socket  send data   how much to send
                          0, (struct sockaddr*) &clientaddr, 
                       // flags   where to send
                          sizeof(clientaddr));
    if (did_send < 0) return errno;
    

    /* 8. You're done! Terminate the connection */     
    close(sockfd);
    return 0;
}