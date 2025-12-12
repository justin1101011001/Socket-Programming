#ifndef encrypt_h
#define encrypt_h


#define BUFFERSIZE 1024
#define KEYBYTES 512
#define KEY_LEN 32        // AES-256 -> 32 bytes
#define IV_LEN 12         // 96-bit
#define TAG_LEN 16        // 128-bit tag

//OpenSSL encryption
EVP_PKEY *generate_rsa_key();
int write_public_key(EVP_PKEY *pkey, unsigned char *buf, size_t buf_len);
int rsa_encrypt_key(unsigned char *asym_public_key, unsigned char *plaintext, size_t plaintext_len, unsigned char *ciphertext, size_t *ciphertext_len);
int rsa_decrypt_key(EVP_PKEY *privkey, unsigned char *ciphertext, size_t ciphertext_len, unsigned char *plaintext, size_t *plaintext_len);
void exchange_key(unsigned char *sym_key, int clientSocket);
int sendMessage(int socket, char *buffer);
int readMessage(int socket, char *buffer);
int sendencryptMessage(int socket, char *buffer, unsigned char *sym_key);
int readencryptMessage(int socket, unsigned char *buffer, unsigned char *sym_key);
int aes256_gcm_encrypt(const unsigned char *key, const unsigned char *iv, int iv_len, const unsigned char *aad, int aad_len,
                                            const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext, unsigned char *out_tag);
int aes256_gcm_decrypt(const unsigned char *key, const unsigned char *iv, int iv_len, const unsigned char *aad, int aad_len,
                                            const unsigned char *ciphertext, int ciphertext_len, const unsigned char *tag, unsigned char *plaintext);
int encryptMessage(char *sendBuffer, unsigned char *encrypt_text, unsigned char *sym_key);
void decryptMessage(unsigned char *recvBuffer, unsigned char *decrypt_text, unsigned char *sym_key, int read_byte);
void handleErrors(const char *msg);
void print_hex(char *name, int len, unsigned char *key); //debug usage


#endif
