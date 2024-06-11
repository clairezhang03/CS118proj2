Dane Guthner: 305692226
Sebastian Caid: 605698463
Claire Zhang: 205736481

Design of Project:
In this project, we implemented a reliable transport layer protocol over UDP that provided basic encryption and server verification features. The project was divided into two main parts:

Reliable Packet Delivery over UDP: Data read from stdin is segmented into chunks of a fixed maximum size (e.g., 1024 bytes) to fit into the payload. Ensuring that any dropped packets are retransmitted and delivered in order from one end to the other. When sending packets, we ensured that each packet was assigned a sequential packet number. We made a congestion window size of 20 packets, allowing multiple packets to be sent before waiting for acknowledgements. 

Upon receiving an acknowledgment, we update the congestion window and reset the retransmission timer. If the acknowledgment number increases, it indicates that the receiver has successfully received packets up to that number. If the sender did not receive an acknowledgment within the expected time (RTO - Retransmission Timeout), it assumes the packet was lost and retransmits it. The timer is set each time a packet is sent. We used a single global timer. When the timer expires, we retransmit the unacknowledged packet with the smallest packet number.

We buffered packets that were received out-of-order and only pass them to the application once all preceding packets have been received. 
  
Basic Cryptographic Features: Utilizing basic cryptographic primitives to encrypt data and verify the server’s cryptographic certificate. We used Diffie-Hellman encoding and a secure handshake. The client
sends a client hello, the server sends a server hello, the client sends a Key Exchange Request and then
the server sends a finished method. When both sides get the corresponding side's public key, they derive
a secret key combined with their private key for encrypting and decrypting. Encrypt-then-MAC allows us to 
add another layer of protection by comparing the MAC codes between what is received and re-hashing the 
data. 

We implemented both the server and client functionalities.

The problems you ran into and how you solved the problems:
1. We had a lot of trouble getting the sending the ack and packet numbers. We realized the numbers
were too large because we did not set the endianness correctly. We used ntohs and htons to 
fix the problem.
2. We had trouble sending the encrypted data and then decrypting it. We wrote a printHex function
to debug this problem and compared both sides, making changes until they both worked.
3. Finding the handshake order was difficult for us. We had to write everything out and print out 
the keys (enc_key, mac_key, secret) out in hex format to figure out that the key exchange request
weren't working.


Acknowledgement of any online tutorials or code examples (except class website) you have been using:
- We used the starter code from the LA website, like using the non-blocking flags.
