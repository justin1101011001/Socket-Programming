#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include "encryption.h"

EVP_PKEY *generate_rsa_key(){
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);

    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    return pkey;   // include public + private key
}

int write_public_key(EVP_PKEY *pkey, unsigned char *buf, size_t buf_len) {
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pkey);

    int len = BIO_read(bio, buf, buf_len);
    BIO_free(bio);
    return len; // return text length
}

int rsa_decrypt_key(EVP_PKEY *privkey, unsigned char *ciphertext,
    size_t ciphertext_len, unsigned char *plaintext, size_t *plaintext_len){
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey, NULL);
    EVP_PKEY_decrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

    EVP_PKEY_decrypt(ctx, NULL, plaintext_len, ciphertext, ciphertext_len);
    EVP_PKEY_decrypt(ctx, plaintext, plaintext_len, ciphertext, ciphertext_len);

    EVP_PKEY_CTX_free(ctx);
    return 1;
}

int rsa_encrypt_key(unsigned char *asym_public_key,
    unsigned char *plaintext, size_t plaintext_len,
    unsigned char *ciphertext, size_t *ciphertext_len){
    //Convert public key to EVP_PKEY structure
    BIO *bio = BIO_new_mem_buf(asym_public_key, -1);
    EVP_PKEY *pubkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pubkey) {
        printf("Failed to parse public key\n");
        return -1;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    EVP_PKEY_encrypt_init(ctx);

    // Use RSA-OAEP
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

    EVP_PKEY_encrypt(ctx, NULL, ciphertext_len, plaintext, plaintext_len);
    EVP_PKEY_encrypt(ctx, ciphertext, ciphertext_len, plaintext, plaintext_len);

    EVP_PKEY_CTX_free(ctx);
    return 1;
}

void exchange_key(unsigned char *sym_key, int clientSocket){
        unsigned char asym_public_key[KEYBYTES]={0};
        unsigned char cipherkeyBuffer[KEYBYTES]={0};
        readMessage(clientSocket, asym_public_key);
        size_t cipher_key_len;
        rsa_encrypt_key(asym_public_key, sym_key, 32, cipherkeyBuffer, &cipher_key_len);
        send(clientSocket, cipherkeyBuffer, cipher_key_len, 0);
        char recvBuffer[BUFFERSIZE];
        readMessage(clientSocket, recvBuffer); //wait for server/chatmate decrypt key
}

int sendMessage(int socket, char *buffer) {
    int32_t messageLength = htonl(strlen(buffer) + 1);
    if (send(socket, &messageLength, sizeof(messageLength), 0) < 0) {
        return -1;
    }
    send(socket, buffer, strlen(buffer) + 1, 0);
    return 0;
}

int sendencryptMessage(int socket, char *buffer, unsigned char *sym_key){
    unsigned char encrypt[BUFFERSIZE]={0};
    int encrypt_len=encryptMessage(buffer, encrypt, sym_key);
    int32_t messageLength = htonl(encrypt_len+1);
    if (send(socket, &messageLength, sizeof(messageLength), 0) < 0) {
        return -1;
    }
    send(socket, encrypt, encrypt_len+1, 0);
    return 0;
}

//int readMessage(int socket, char *buffer) {
//    int32_t messageLength;
//    read(socket, &messageLength, sizeof(messageLength));
//    int r=read(socket, buffer, ntohl(messageLength));
//    return r;
//}

int readMessage(int socket, char *buffer) {
    int32_t networkLength;
    int bytesRead = 0;
    int result;

    // 1. Read the length (Loop to ensure we get all 4 bytes)
    while (bytesRead < sizeof(networkLength)) {
        result = read(socket, ((char*)&networkLength) + bytesRead, sizeof(networkLength) - bytesRead);
        if (result < 0) return -1; // Error
        if (result == 0) return 0; // Connection closed
        bytesRead += result;
    }

    int32_t messageLength = ntohl(networkLength);

    // 2. SAFETY CHECK: Prevent Stack Smashing
    if (messageLength > BUFFERSIZE || messageLength < 0) {
        printf("Error: Message too long (%d) for buffer (%d)\n", messageLength, BUFFERSIZE);
        return -1; // Or handle error appropriately
    }

    // 3. Read the body (Loop to ensure we get the full message)
    bytesRead = 0;
    while (bytesRead < messageLength) {
        result = read(socket, buffer + bytesRead, messageLength - bytesRead);
        if (result < 0) return -1;
        if (result == 0) return 0;
        bytesRead += result;
    }

    // Null-terminate explicitly if treating as string, though binary data doesn't care
    if (bytesRead < BUFFERSIZE) {
        buffer[bytesRead] = '\0';
    }
    
    return bytesRead;
}

int readencryptMessage(int socket, unsigned char *buffer, unsigned char *sym_key){
    unsigned char encrypt[BUFFERSIZE]={0};
    int r=readMessage(socket, (char *)encrypt);
    if(r==0) return 0;
    decryptMessage(encrypt, buffer, sym_key, r-1);
    return (int)strlen((char *)buffer);
}

int aes256_gcm_encrypt(
    const unsigned char *key,
    const unsigned char *iv, int iv_len,
    const unsigned char *aad, int aad_len,
    const unsigned char *plaintext, int plaintext_len,
    unsigned char *ciphertext,
    unsigned char *out_tag) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, ciphertext_len = 0;
    int ret = -1;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors("EVP_CIPHER_CTX_new failed");

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors("EncryptInit_ex failed");

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors("Set IV length failed");

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors("EncryptInit_ex set key/iv failed");

    // Provide AAD data if any
    if (aad && aad_len > 0) {
        if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
            handleErrors("EncryptUpdate AAD failed");
    }

    // Encrypt plaintext
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors("EncryptUpdate plaintext failed");
    ciphertext_len = len;

    // Finalize
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors("EncryptFinal_ex failed");
    ciphertext_len += len;

    // Get tag
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, out_tag))
        handleErrors("Get tag failed");

    ret = ciphertext_len;

    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int aes256_gcm_decrypt(
    const unsigned char *key,
    const unsigned char *iv, int iv_len,
    const unsigned char *aad, int aad_len,
    const unsigned char *ciphertext, int ciphertext_len,
    const unsigned char *tag,
    unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, plaintext_len = 0;
    int ret = -1;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors("EVP_CIPHER_CTX_new failed");

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors("DecryptInit_ex failed");

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors("Set IV length failed");

    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors("DecryptInit_ex set key/iv failed");

    // AAD
    if (aad && aad_len > 0) {
        if (1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
            handleErrors("DecryptUpdate AAD failed");
    }

    // Decrypt ciphertext
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors("DecryptUpdate ciphertext failed");
    plaintext_len = len;

    // Set expected tag value
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void *)tag)) {
        handleErrors("Set tag failed");
    }

    // Finalize: returns 1 if tag verifies, 0 if verification fails
    int rv = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (rv > 0) {
        plaintext_len += len;
        ret = plaintext_len;
    } else {
        // Authentication failed
        ret = -1;
    }
    return ret;
}

int encryptMessage(char *sendBuffer, unsigned char *encrypt_text, unsigned char *sym_key){
        unsigned char iv[IV_LEN+1];
        unsigned char tag[TAG_LEN+1];
        RAND_bytes(iv, IV_LEN);
        int c_len=aes256_gcm_encrypt(sym_key, iv, IV_LEN, NULL, 0,
                        (unsigned char *)sendBuffer, (int)strlen(sendBuffer), encrypt_text, tag);
        encrypt_text[c_len]='\0';
        char encrypt_packet[BUFFERSIZE]={0};
        memcpy(encrypt_packet, iv, IV_LEN);
        memcpy(encrypt_packet+IV_LEN, encrypt_text, c_len);
        memcpy(encrypt_packet+IV_LEN+c_len, tag, TAG_LEN);
        memset(encrypt_text, '\0', BUFFERSIZE);
        memcpy(encrypt_text, encrypt_packet, c_len+IV_LEN+TAG_LEN);
        return c_len+IV_LEN+TAG_LEN;
}

void decryptMessage(unsigned char *recvBuffer, unsigned char *decrypt_text, unsigned char *sym_key, int read_byte){
    unsigned char iv[IV_LEN+1]={};
    unsigned char ciphertext[BUFFERSIZE]={};
    unsigned char tag[TAG_LEN+1]={};
    memcpy(iv, recvBuffer, IV_LEN);
    memcpy(ciphertext, recvBuffer+IV_LEN, read_byte-IV_LEN-TAG_LEN);
    memcpy(tag, recvBuffer+read_byte-TAG_LEN, TAG_LEN);
    int p_len=aes256_gcm_decrypt(sym_key, iv, IV_LEN, NULL, 0, ciphertext, read_byte-IV_LEN-TAG_LEN, tag, decrypt_text);
    decrypt_text[p_len]='\0';
}

void handleErrors(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

void print_hex(char *name, int len, unsigned char *key){
    printf("%s(%d):\n", name, len);
    for(int i=0; i<len; i++) printf("%02x", key[i]);
    printf("\n");
}
