#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdio.h>

#include "security.h"

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
    return ret == 1;
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

//helper function to create self-signed certificate
void create_self_signed_cert(char **cert, size_t *cert_size) {
    //CHANGE
    //key length and padding, pub key size, 255 bytes for signature
    *cert_size = 4 + pub_key_size + 255; 
    *cert = (char *)malloc(*cert_size);

    //use helper
    write_int_to_buffer(*cert, pub_key_size, 2);
    memset(*cert + 2, 0, 2); //padding
    memcpy(*cert + 4, public_key, pub_key_size);
    
    //sign the public key
    char signature[255];
    size_t sig_size = sign(public_key, pub_key_size, signature);
    memcpy(*cert + 4 + pub_key_size, signature, sig_size);

    *cert_size = 4 + pub_key_size + sig_size;
}

//ClientHello message
void create_client_hello(char **message, size_t *message_size, int comm_type) {
    //CHANGE
    //CommType and Padding, nonce
    *message_size = 4 + 32;
    *message = (char *)malloc(*message_size);

    (*message)[0] = comm_type;
    memset(*message + 1, 0, 3); //padding
    generate_nonce(*message + 4, 32);
}

//ServerHello message
void create_server_hello(char **message, size_t *message_size, int comm_type, char *client_nonce, size_t client_nonce_size) {
    char server_nonce[32];
    generate_nonce(server_nonce, 32);

    //create server certificate
    char *server_cert;
    size_t server_cert_size;
    create_self_signed_cert(&server_cert, &server_cert_size);

    //sign client nonce
    char signature[255];
    size_t sig_size = sign(client_nonce, client_nonce_size, signature);

    //CHANGE
    //CommType SigSize and CertSize, nonce, server_cert_size, signature
    *message_size = 4 + 32 + server_cert_size + sig_size;
    *message = (char *)malloc(*message_size);

    (*message)[0] = comm_type;
    (*message)[1] = sig_size;
    write_int_to_buffer(*message + 2, server_cert_size, 2);
    memcpy(*message + 4, server_nonce, 32);
    memcpy(*message + 36, server_cert, server_cert_size);
    memcpy(*message + 36 + server_cert_size, signature, sig_size);

    free(server_cert);
}

//KeyExchangeRequest message
void create_key_exchange_request(char **message, size_t *message_size, char *server_nonce, size_t server_nonce_size) {
    //create client certificate
    char *client_cert;
    size_t client_cert_size;
    create_self_signed_cert(&client_cert, &client_cert_size);

    //sign server nonce
    char signature[255];
    size_t sig_size = sign(server_nonce, server_nonce_size, signature);

    //CHANGE
    //Padding SigSize and CertSize, client_cert_size, signature
    *message_size = 4 + client_cert_size + sig_size;
    *message = (char *)malloc(*message_size);

    memset(*message, 0, 1); //padding
    (*message)[1] = sig_size;
    write_int_to_buffer(*message + 2, client_cert_size, 2);
    memcpy(*message + 4, client_cert, client_cert_size);
    memcpy(*message + 4 + client_cert_size, signature, sig_size);

    free(client_cert);
}

//Data message
void create_data_message(char **message, size_t *message_size, char *data, size_t data_size, int using_mac) {
    char iv[IV_SIZE];
    char encrypted_data[data_size + IV_SIZE]; 
    //note: padded data size can be up to AES_BLOCK_SIZE bytes larger than input data size
    size_t encrypted_data_size = encrypt_data(data, data_size, iv, encrypted_data, using_mac);

    //compute HMAC -- if using mac
    char mac[MAC_SIZE];
    if (using_mac) {
        char *mac_data = (char *)malloc(IV_SIZE + encrypted_data_size);
        memcpy(mac_data, iv, IV_SIZE);
        memcpy(mac_data + IV_SIZE, encrypted_data, encrypted_data_size);
        hmac(mac_data, IV_SIZE + encrypted_data_size, mac);
        free(mac_data);
    }

    //PayloadSize and Padding, IV_SIZE, encrypted_data_size, optional MAC_SIZE
    *message_size = 4 + IV_SIZE + encrypted_data_size + (using_mac ? MAC_SIZE : 0);
    *message = (char *)malloc(*message_size);

    write_int_to_buffer(*message, encrypted_data_size, 2);
    memset(*message + 2, 0, 2); //padding
    memcpy(*message + 4, iv, IV_SIZE);
    memcpy(*message + 4 + IV_SIZE, encrypted_data, encrypted_data_size);
    if (using_mac) {
        memcpy(*message + 4 + IV_SIZE + encrypted_data_size, mac, MAC_SIZE);
    }
}

//fun test implementation
// Implement the main logic to simulate the protocol
int main() {
    // Step 1: Generate private key and derive public key
    generate_private_key();
    derive_public_key();

    // Step 2: Client generates ClientHello message
    char *client_hello;
    size_t client_hello_size;
    create_client_hello(&client_hello, &client_hello_size, 1);

    // Step 3: Server generates ServerHello message
    char *server_hello;
    size_t server_hello_size;
    create_server_hello(&server_hello, &server_hello_size, 1, client_hello + 4, 32);

    // Step 4: Client generates KeyExchangeRequest message
    char *key_exchange_request;
    size_t key_exchange_request_size;
    create_key_exchange_request(&key_exchange_request, &key_exchange_request_size, server_hello + 4, 32);

    // Step 5: Derive shared secret and keys
    load_peer_public_key(server_hello + 36, server_hello_size - 36);
    derive_secret();
    derive_keys();

    // Step 6: Client sends encrypted data
    char *data = "Hello, secure world!";
    char *data_message;
    size_t data_message_size;
    create_data_message(&data_message, &data_message_size, data, strlen(data), 1);

    // Clean up
    free(client_hello);
    free(server_hello);
    free(key_exchange_request);
    free(data_message);
    clean_up();

    return 0;
}