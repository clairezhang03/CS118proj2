#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <iostream>
#include <stdio.h>
#include <arpa/inet.h>
#include "security.h"
#include "utils.h"

using namespace std;

EVP_PKEY* ec_priv_key = NULL;
EVP_PKEY* ec_peer_public_key = NULL;
EVP_PKEY* ec_ca_public_key = NULL; 

int cert_size = 0;
char* certificate = NULL;
int pub_key_size = 0;
char* public_key = NULL;
char* secret = NULL;
char* enc_key = NULL;
char* mac_key = NULL;

void load_private_key(char* filename) {
    FILE* fp = fopen(filename, "r");
    ec_priv_key = d2i_PrivateKey_fp(fp, NULL);
    fclose(fp);
}

void load_peer_public_key(char* peer_key, size_t size) {
    BIO* bio = BIO_new_mem_buf(peer_key, size);
    ec_peer_public_key = d2i_PUBKEY_bio(bio, NULL);
    BIO_free(bio);
}

void load_ca_public_key(char* filename) {
    FILE* fp = fopen(filename, "r");
    ec_ca_public_key = d2i_PUBKEY_fp(fp, NULL);
    fclose(fp);
}

void load_certificate(char* filename) {
    FILE* fp = fopen(filename, "r");
    char* cert;

    fseek(fp, 0, SEEK_END);
    cert_size = ftell(fp);
    cert = (char*) malloc(cert_size);
    fseek(fp, 0, 0);
    fread(cert, cert_size, 1, fp);
    certificate = cert;
    fclose(fp);
}

void generate_private_key() {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);

    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
    EVP_PKEY_keygen(pctx, &ec_priv_key);

    EVP_PKEY_CTX_free(pctx);
}

void derive_public_key() {
    pub_key_size = i2d_PUBKEY(ec_priv_key, (unsigned char**) &public_key);
}

void derive_secret() {
    size_t sec_size = SECRET_SIZE;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(ec_priv_key, NULL);

    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, ec_peer_public_key);
    secret = (char*) malloc(sec_size);
    EVP_PKEY_derive(ctx, (unsigned char*) secret, &sec_size);

    EVP_PKEY_CTX_free(ctx);
}

void derive_keys() {
    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx;
    OSSL_PARAM params[4];
    
    kdf = EVP_KDF_fetch(NULL, "hkdf", NULL);
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf); 

    params[0] = OSSL_PARAM_construct_utf8_string("digest", (char*) "sha256", (size_t) 7);
    params[1] = OSSL_PARAM_construct_octet_string("key", (char*) secret, (size_t) SECRET_SIZE);
    params[2] = OSSL_PARAM_construct_octet_string("info", (char*) "enc", (size_t) 3);
    params[3] = OSSL_PARAM_construct_end();
    EVP_KDF_CTX_set_params(kctx, params);

    enc_key = (char*) malloc(SECRET_SIZE);
    EVP_KDF_derive(kctx, (unsigned char*) enc_key, SECRET_SIZE, NULL);

    params[2] = OSSL_PARAM_construct_octet_string("info", (char*) "mac", (size_t) 3);
    EVP_KDF_CTX_set_params(kctx, params);

    mac_key = (char*) malloc(SECRET_SIZE);
    EVP_KDF_derive(kctx, (unsigned char*) mac_key, SECRET_SIZE, NULL);

    EVP_KDF_CTX_free(kctx);
}

size_t sign(char* data, size_t size, char* signature) {
    size_t sig_size = 255;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, ec_priv_key);
    EVP_DigestSignUpdate(mdctx, data, size);
    EVP_DigestSignFinal(mdctx, (unsigned char*) signature, &sig_size);

    EVP_MD_CTX_free(mdctx);
    return sig_size;
}

int verify(char* data, size_t size, char* signature, size_t sig_size, EVP_PKEY* authority) {
    // TODO: Implement this yourself! Hint: it's very similar to `sign`. 
    // See https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    int ret;

    EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, authority);
    EVP_DigestVerifyUpdate(mdctx, data, size);
    ret = EVP_DigestVerifyFinal(mdctx, (unsigned char*)signature, sig_size);

    EVP_MD_CTX_free(mdctx);
    return ret;
}

void generate_nonce(char* buf, int size) {
    RAND_bytes((unsigned char*) buf, size);
}

size_t encrypt_data(char *data, size_t size, char *iv, char *cipher, int using_mac) {
    int cipher_size;
    int padding_size;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    generate_nonce(iv, IV_SIZE);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char*) (using_mac ? enc_key : secret), (const unsigned char*) iv);
    EVP_EncryptUpdate(ctx, (unsigned char*) cipher, &cipher_size, (const unsigned char*) data, size);
    EVP_EncryptFinal_ex(ctx, (unsigned char*) cipher + cipher_size, &padding_size);

    EVP_CIPHER_CTX_free(ctx);

    return cipher_size + padding_size;
}

size_t decrypt_cipher(char *cipher, size_t size, char *iv, char *data, int using_mac) {
    // TODO: Implement this yourself! Hint: it's very similar to `encrypt_data`.
    // See https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
    int plain_size;
    int final_size;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char*) (using_mac ? enc_key : secret), (const unsigned char*) iv);
    EVP_DecryptUpdate(ctx, (unsigned char*) data, &plain_size, (const unsigned char*) cipher, size);
    EVP_DecryptFinal_ex(ctx, (unsigned char*) data + plain_size, &final_size);

    EVP_CIPHER_CTX_free(ctx);

    return plain_size + final_size;
}

void hmac(char* data, size_t size, char* digest) {
    unsigned int mac_size = MAC_SIZE;
    HMAC(EVP_sha256(), mac_key, SECRET_SIZE, (const unsigned char*) data, size, (unsigned char*) digest, &mac_size);
}

void clean_up() {
    if (ec_priv_key) EVP_PKEY_free(ec_priv_key);
    if (ec_peer_public_key) EVP_PKEY_free(ec_peer_public_key);
    if (ec_ca_public_key) EVP_PKEY_free(ec_ca_public_key);
    if (certificate) free(certificate);
    if (public_key) free(public_key);
    if (secret) free(secret);
    if (enc_key) free(enc_key);
    if (mac_key) free(mac_key);
}

//start of add. code

//helper - write integers in network order
void write_int_to_buffer(char *buffer, int value, int size) {
    int net_value = htonl(value);
    memcpy(buffer, &net_value, size);
}

void printHex(char* data, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        printf("%02x ", static_cast<unsigned char>(data[i]));
    }
    printf("\n");
}

//helper function to create self-signed certificate
// void create_self_signed_cert(struct Certificate* cert, size_t *cert_size) {
//     //CHANGE
//     cert->KeyLength = htons(pub_key_size); // cast?
//     cert->Padding = htons(0);
//     cert->PublicKey = public_key;

//     //sign the public key
//     char signature[255];
//     size_t sig_size = sign(public_key, pub_key_size, signature);
//     memcpy(cert->Signature, signature, sig_size);

//     // *cert_size = 4 + pub_key_size + sig_size;
//     *cert_size = sizeof(&cert);
// }

// ClientHello message
void create_client_hello(struct ClientHello* client_hello, uint8_t comm_type) {
    struct SecurityHeader header;
    header.MsgType = 1;
    header.Padding = 0;
    header.MsgLen = htons(33); //CHECK
    client_hello->Header = header;

    client_hello->CommType = comm_type;

    client_hello->Padding[0] = 0;
    client_hello->Padding[1] = 0;
    client_hello->Padding[2] = 0;

    char client_nonce[32];
    generate_nonce(client_nonce, 32);
    memcpy(&client_hello->ClientNonce, client_nonce, 32);
}

void parse_certificate(char* cert_data, struct Certificate* cert, uint16_t size){
    // cout << size << endl;
    cert_size = size;

    cert = (Certificate*)::operator new(cert_size);
    // cert->KeyLength = ntohs(*(uint16_t*)cert_data);
    // cout << "key length" << cert->KeyLength << endl;
    // cert_data += sizeof(uint16_t);

    // cert->Padding = 0;
    // cert_data += sizeof(uint16_t);

    // char public_key_sig[cert_size - 4];
    memcpy(cert, cert_data, cert_size);
    // cert->PublicKey_Signature = public_key_sig;
}

//ServerHello message
size_t create_server_hello(struct ServerHello* server_hello, uint8_t comm_type, char* client_nonce, char* certificate_file, char* private_key_file) {

    uint16_t c_size = htons(cert_size);
    // uint16_t converted_cert_size = htons(cert_size);
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
    cout << sig_size << endl;
    cout << s_size << endl;
    memcpy(message + sizeof(header) + sizeof(comm_type) + sizeof(s_size) + sizeof(c_size) + 32 + cert_size, &signature, sig_size);

    cout << sizeof(message) << endl;
    memcpy(server_hello, message, sizeof(message));

    return sizeof(message);
}

int call_verify_cert(char* data, size_t size, char* signature, uint16_t key_length){
    return verify(data, size, signature, cert_size - 4 - key_length, ec_ca_public_key);
}

int call_verify_nonce(char* data, size_t size, char* signature, uint8_t sig_size){
    return verify(data, size, signature, sig_size, ec_peer_public_key);
}

//KeyExchangeRequest message
void create_key_exchange_request(struct KeyExchangeRequest* key_exchange, char *server_nonce) {
    //create client certificate
    // key_exchange->Padding = 0;

    // struct Certificate client_cert;
    // size_t client_cert_size;
    // create_self_signed_cert(&client_cert, &client_cert_size);
    // key_exchange->CertSize = htons(client_cert_size);
    // key_exchange->ClientCertificate = client_cert;

    // //sign server nonce
    // char signature[255];
    // size_t sig_size = sign(server_nonce, 32, signature);
    // memcpy(key_exchange->ServerNonceSignature, signature, sig_size);
    // key_exchange->SigSize = sig_size;

    // struct SecurityHeader header;
    // header.MsgType = 16;
    // header.Padding = 0;
    // header.MsgLen = htons(4 + sig_size + cert_size); //CHECK
    // key_exchange->Header = header;
}

//Data message
void create_data_message(struct DataMessage* data_message, uint16_t payload_size, char *payload, int using_mac) {
    data_message->PayloadSize = htons(payload_size);
    data_message->Padding = 0;

    char iv[IV_SIZE];
    char encrypted_payload[payload_size]; 
    //note: padded data size can be up to AES_BLOCK_SIZE bytes larger than input data size
    size_t encrypted_payload_size = encrypt_data(payload, payload_size, iv, encrypted_payload, using_mac);
    memcpy(data_message->IV, iv, IV_SIZE);
    memcpy(data_message->payload, encrypted_payload, encrypted_payload_size);

    //compute HMAC -- if using mac
    char mac[MAC_SIZE];
    if (using_mac) {
        char *mac_data = (char *)malloc(IV_SIZE + encrypted_payload_size);
        memcpy(mac_data, iv, IV_SIZE);
        memcpy(mac_data + IV_SIZE, encrypted_payload, encrypted_payload_size);
        hmac(mac_data, IV_SIZE + encrypted_payload_size, mac);
        free(mac_data);
        memcpy(data_message->MACcode, mac, MAC_SIZE);
    }

    struct SecurityHeader header;
    header.MsgType = 255;
    header.Padding = 0;
    if (using_mac){
        header.MsgLen = htons(52 + payload_size); //CHECK
    }
    else{
        header.MsgLen = htons(20 + payload_size); //CHECK
    }
    data_message->Header = header;
}

//fun test implementation
// Implement the main logic to simulate the protocol
// int main() {
//     // Step 1: Generate private key and derive public key
//     generate_private_key();
//     derive_public_key();

//     // Step 2: Client generates ClientHello message
//     char *client_hello;
//     size_t client_hello_size;
//     create_client_hello(&client_hello, &client_hello_size, 1);

//     // Step 3: Server generates ServerHello message
//     char *server_hello;
//     size_t server_hello_size;
//     create_server_hello(&server_hello, &server_hello_size, 1, client_hello + 4, 32);

//     // Step 4: Client generates KeyExchangeRequest message
//     char *key_exchange_request;
//     size_t key_exchange_request_size;
//     create_key_exchange_request(&key_exchange_request, &key_exchange_request_size, server_hello + 4, 32);

//     // Step 5: Derive shared secret and keys
//     load_peer_public_key(server_hello + 36, server_hello_size - 36);
//     derive_secret();
//     derive_keys();

//     // Step 6: Client sends encrypted data
//     char *data = "Hello, secure world!";
//     char *data_message;
//     size_t data_message_size;
//     create_data_message(&data_message, &data_message_size, data, strlen(data), 1);

//     // Clean up
//     free(client_hello);
//     free(server_hello);
//     free(key_exchange_request);
//     free(data_message);
//     clean_up();

//     return 0;
// }

//plan:

//We can define in utils the size of a nonce to be 32
	// To begin, the client must send a client_hello message to initiate the secure connection. This message contains a random number and a communication type (0 for encryption only mode, and 1 for encrypt-then-mac mode). In client.cpp
	// 1.	Construct client_hello
	// 2.	Use generate_nonce to create the nonce to put into client_hello
// 2.	The server will respond with a server_hello message. This message contains a random number, the server’s certificate, and a signature over the client random number. In server.cpp
	// 1.	Comm_type: copy from client, we should store this in a flag so we know whether to do encrypt-then-MAC
	// 2.	Sig_size: returned by sign function when signing client_nonce
	// 3.	Cert_size: sizeof(certificate)? IN NETWORK BYTES: NEED TO CONVERT ENDIANNESS
	// 4.	Server_nonce: Use generate_nonce to create the nonce to put into server_hello
	// 5.	Server certificate: Server is passed in <certificate_file> as the last argument: in variable certificate_file, Server’s certificate for its public key (CA is verifying that server is who they say they are):
	// 1.	Use load_certificate(certificate_file) to load signed certificate into buffer “certificate”: the server has obtained this certificate from a CA (who has signed it), a trustable source and it encodes the server’s public key. The server will send it over to the client who will decode it + can trust the server’s identity
	// 6.	Signature over client’s random number (the nonce): server has a private key file passed in as an argument, stored in private_key_file
	// 1.	load_private_key(private_key_file)—> server’s private key will be stored in ec_priv_key (global variable in security.cpp). ec_priv_key will be used to sign the client’s nonce
	// 2.	Extract client’s nonce from the payload
	// 3.	Use signature_size = sign(client_nonce, 32 bytes, signature): You will have to pass in a char* signature that will store the signature. Use the returned signature_size in construction of server_hello
// 3.	The client must verify the signatures of the certificate and of the random number. If any signature is not valid, the connection must be terminated and the client exits. In client.cpp
	// 1.	Verifying the certificate
	// 1.	From server_hello, extract the certificate and extract the certificate signature
	// 2.	load_ca_public_key(ca_public_key_file) —> public key of CA is now stored in ec_ca_public_key: will use this to decrypt the certificate (which contains its public key) the server sent/ use CA public key to decrypt the CA verified server’s public key
	// 3.	verify(certificate, certificate size, certificate_signature, certificate signature size, ec_ca_public_key)
	// 2.	Verify the signature of client’s nonce: verify(client_nonce, 32 bytes, signature from server hello, signature size from server hello, ec_ca_public_key)
	// 1.	If 0 —> not verified, terminate connection
// 4.	The client now uses Diffie-Hellman to create the shared secret encryption key. In client.cpp
	    // 1.	Create a private key for the client: generate_private_key()—> stored in ec_priv_key
	    // 2.	Create a public key for the client: derive_public_key() , needs to be done after generating private key
	    // 3.	load_peer_public_key(public key in certificate from server_hello) —> stores public key into ec_peer_public_key
	    // 4.	derive_secret() —> stores secret shared key into secret
	    // 5.	If comm_type is 1: derive_keys() —> get the MAC key, shared encryption key
// 5.	The client generates a temporary key pair and sends the key_exchange_request message, containing the client’s self-signed certificate. The server uses the certificate to generate the same shared secret key.
	// 1.	Generate a client certificate: use public key that it generated + signature which is the public key signed by the private key
	    // 1.	Use the sign function
	    // 2.	Use sign function to sign server’s nonce()
	    // 3.	Send to server
// 6.	The server sends a finished message, containing no payload. In server.cpp
	    // 1.	(Don’t need to verify client’s nonce because it’s not tested)
	    // 2.	Load in private key file of server: load_private_key(private_key_file)<— this will be stored in ec_priv_key
	// 3.	load_peer_public_key(client’s public key from key_exchange_request)
	// 4.	derive_secret() —> server now knows the secret
	// 5.	If comm_type : 1 derive_keys() —> get the MAC key, shared encryption key
	// 7.	Both sides can now start transmitting data messages, containing encrypted application layer data. Each data message must be encrypted using the shared secret obtained with Diffie-Hellman.
	// 1.	Now send messages by using encrypt()
	// 2.	Receive messages using decrypt()
	// 3.	Call clean_up at the end()
    //CALL HMAC NOT WITH 32