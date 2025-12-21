#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <pthread.h>
#include <ncurses.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>

typedef struct evp_pkey_st EVP_PKEY; // Forward declaration to avoid including OpenSSL headers here
int RAND_bytes(unsigned char *buf, int num); // Forward declaration for RAND_bytes

#include "client.h"
#include "encryption.h"

#define SERVERPORT 12014
#define BUFFERSIZE 1024
#define TIMEWINDOWWIDTH 18

static pthread_t messageReciever;
static pthread_t DMAcceptor;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t drawWindow = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t readyToAccept = PTHREAD_COND_INITIALIZER; // Used by acceptDM to indicate readiness to accept the next connection from a peer
pthread_cond_t readyToAcceptFile = PTHREAD_COND_INITIALIZER; // Used to accept incoming file transfers
bool acceptSignal = false; // DM request accpeted, used by acceptDM to indicate readiness to accept the next connection from a peer
bool fileAcceptSignal = false; // File transfer accepted signal
bool DMOngoing = false; // Flag indicating if there's an ongoing DM session
bool pendingRequest = false; // Flag indicating if there's a pending DM request from a peer
bool filePendingRequest = false; // Is there a pending file transfer request?
int fileSocket = -1; // Accepted socket for incoming file transfer
char incomingFileSender[BUFFERSIZE] = "";
char incomingFileName[BUFFERSIZE] = "";
long long incomingFileSize = 0;

char currentUserID[100] = "";
char currentPeerID[100] = "";
char lastMessageSentBy[100] = ""; // Who sent the last message? Used for message window drawing

int peerSocket; // Used for DM with a peer

// Used for encryption of DM
unsigned char my_asym_public_key[KEYBYTES]={0};
EVP_PKEY *asym_key;
unsigned char chat_sym_key[KEY_LEN]={0};
static unsigned char file_sym_key[KEY_LEN] = {0};

int main(int argc, char const* argv[]) {
//MARK: - Socket Setup
    int listeningPort = setListeningPort(argc, argv); // Get listening port from arguments
    int listeningSocket = 0, clientSocket = 0;
    listeningSocket = setListeningSocket(listeningSocket, listeningPort); // Set listening socket

    unsigned char recvBuffer[BUFFERSIZE] = {0}; // buffer for messages from server
    char inputBuffer[BUFFERSIZE] = {0}; // buffer for user input
    bool loggedIn = false; // is the user currently logged in

    // Create thread to accept DM requests
    if (pthread_create(&DMAcceptor, NULL, acceptDM, &listeningSocket) != 0) {
        perror(RED("[ERROR]")" Failed to create DM acceptor thread\n");
        exit(EXIT_FAILURE);
    }

    unsigned char sym_key[KEY_LEN]={0};

    //generate RSA key for DM
    asym_key=generate_rsa_key();
    int w=write_public_key(asym_key, my_asym_public_key, KEYBYTES);

    while (true) {
        printf(BOLD("%s> "), currentUserID);
        fflush(stdout);
        fgets(inputBuffer, BUFFERSIZE, stdin); // read whole line of input
        inputBuffer[strcspn(inputBuffer, "\n")] = '\0'; // trim off the newline character at the end
        char *token; // Pointer to store each token
        token = strtok(inputBuffer, " "); // Get the first token of input
        if (token == NULL) { // Empty command, continue reading
            continue;
        }

//MARK: - Exit
        if (strcmp(token, "exit") == 0) { // exit and end the client process
            if (loggedIn) {
                strcpy(token, "logout");
                sendencryptMessage(clientSocket, token, sym_key);
                readencryptMessage(clientSocket, recvBuffer, sym_key);
                close(clientSocket);

                loggedIn = false;
                printf("%s", recvBuffer);
            }
            break;

//MARK: - Logout
        } else if (strcmp(token, "logout") == 0) { // logout put keeps the client process running
            if (!loggedIn) {
                printf("You are currently not logged in to any account.\n");
                continue;
            }

            sendencryptMessage(clientSocket, token, sym_key);
            readencryptMessage(clientSocket, recvBuffer, sym_key);
            close(clientSocket);
            currentUserID[0] = '\0';
            loggedIn = false;
            printf("%s", recvBuffer);

//MARK: - Register
        } else if (strcmp(token, "register") == 0) {
            char sendBuffer[BUFFERSIZE] = "";
            int parameterIndex = parseInput(token, sendBuffer, NULL);

            if (parameterIndex == 3) { // correct number of parameters
                if (loggedIn) {
                    printf("You are already logged in to an account, please logout before creating a new account.\n");
                    continue;
                }

                clientSocket = connectToServer(clientSocket);
                if (clientSocket < 0) continue;

                // create symmetric key
                if (1 != RAND_bytes(sym_key, sizeof(sym_key))) handleErrors("RAND_bytes key failed");
                exchange_key(sym_key, clientSocket);

                sendencryptMessage(clientSocket, sendBuffer, sym_key);
                readencryptMessage(clientSocket, recvBuffer, sym_key);
                close(clientSocket);
                printf("%s", recvBuffer);
            } else {
                printf("Invalid parameters.\nUsage: register <ID> <password>\n");
            }

//MARK: - Deregister
        } else if (strcmp(token, "deregister") == 0) {
            if (!loggedIn) { // Can't deregister without logging in
                printf("Please log in first to start the deregistration process.\n");
                continue;
            }

            char sendBuffer[BUFFERSIZE] = "";
            int parameterIndex = parseInput(token, sendBuffer, NULL);

            if (parameterIndex == 2) {
                sendencryptMessage(clientSocket, sendBuffer, sym_key); // Send deregistration request
                readencryptMessage(clientSocket, recvBuffer, sym_key); // Read comfirmation message
                printf("%s", recvBuffer);

                if (strncmp(recvBuffer, "You", 3) == 0) { // Password check passed
                    // User input to confirm deregistration
                    printf(BOLD("%s> "), currentUserID);
                    fgets(inputBuffer, BUFFERSIZE, stdin); // read whole line of input
                    inputBuffer[strcspn(inputBuffer, "\n")] = '\0'; // trim off the newline character at the end
                    sendencryptMessage(clientSocket, inputBuffer, sym_key); // Send comfirmation
                    readencryptMessage(clientSocket, recvBuffer, sym_key); // Server response

                    if (strncmp(recvBuffer, "Success", 7) == 0) { // Deregistered successsfully
                        close(clientSocket);
                        currentUserID[0] = '\0';
                        loggedIn = false;
                    }

                    printf("%s", recvBuffer);
                }
            } else {
                printf("Invalid parameters.\nUsage: deregister <password>\n");
            }

//MARK: - Login
        } else if (strcmp(token, "login") == 0) {
            char sendBuffer[BUFFERSIZE] = "";
            char inputTokens[3][BUFFERSIZE] = {0}; // 1 ID, 2 password
            int parameterIndex = parseInput(token, sendBuffer, inputTokens);

            if (parameterIndex == 3) { // correct number of parameters
                if (loggedIn) {
                    printf("You are already logged in to an account, please logout before logging in to another account.\n");
                    continue;
                }

                clientSocket = connectToServer(clientSocket);
                if (clientSocket < 0) continue;

                if (1 != RAND_bytes(sym_key, sizeof(sym_key))) handleErrors("RAND_bytes key failed");
                exchange_key(sym_key, clientSocket);

                sendencryptMessage(clientSocket, sendBuffer, sym_key);
                readencryptMessage(clientSocket, recvBuffer, sym_key);

                if (strncmp(recvBuffer, "OK.", 3) == 0) { // if successfully logged in
                    unsigned char str_format[5]={};
                    int32_t formatted = htons(listeningPort); // Send listening port
                    memcpy(str_format, &formatted, sizeof(int32_t)); // Transfer port number into string
                    sendencryptMessage(clientSocket, (char *)str_format, sym_key);

                    loggedIn = true;
                    strcpy(currentUserID, inputTokens[1]); // Add logged in user name to prompt
                    readencryptMessage(clientSocket, recvBuffer, sym_key);
                }

                printf("%s", recvBuffer);
            } else {
                printf("Invalid parameters.\nUsage: login <ID> <password>\n");
            }

//MARK: - List
        } else if (strcmp(token, "list") == 0) {
            if (!loggedIn) {
                printf("You are currently not logged in, plaese login to use this feature.\n");
                continue;
            }

            sendencryptMessage(clientSocket, token, sym_key);
            readencryptMessage(clientSocket, recvBuffer, sym_key);
            printf(GREEN("Online Users\n====================\n"));
            while (strcmp(recvBuffer, "END OF USER LIST") != 0) {
                printf(GREEN("%s\n"), recvBuffer);
                readencryptMessage(clientSocket, recvBuffer, sym_key);
            }

//MARK: - DM
        } else if (strcmp(token, "chat") == 0) {
            char sendBuffer[BUFFERSIZE] = "";
            char inputTokens[2][BUFFERSIZE] = {0}; // 1 peerID
            int parameterIndex = parseInput(token, sendBuffer, inputTokens);

            if (parameterIndex == 2) { // correct number of parameters
                if (!loggedIn) {
                    printf("You are currently not logged in, plaese login to use this feature.\n");
                    continue;
                }
                if (strcmp(inputTokens[1], currentUserID) == 0) { // Don't allow messaging oneself
                    printf("??? Make some friends???\n");
                    continue;
                }
                if (DMOngoing) {
                    printf(RED("Cannot have more than one ongoing chat at once.\n"));
                    continue;
                }

                // Get peer address from server
                sendencryptMessage(clientSocket, sendBuffer, sym_key);
                readencryptMessage(clientSocket, recvBuffer, sym_key);
                if (strncmp(recvBuffer, "Peer", 4) == 0) { // Peer offline
                    printf("%s", recvBuffer);
                    continue;
                }

                struct sockaddr_in peerAddress;
                socklen_t addrlen = sizeof(peerAddress); // length of address
                peerAddress.sin_family = AF_INET; // address family is IPv4
                unsigned char str_addr[5]={}, str_port[3]={};
                readencryptMessage(clientSocket, str_addr, sym_key);
                readencryptMessage(clientSocket, str_port, sym_key);
                memcpy(&(peerAddress.sin_addr.s_addr), str_addr, sizeof(in_addr_t));
                memcpy(&(peerAddress.sin_port), str_port, sizeof(in_port_t));
                //read(clientSocket, &(peerAddress.sin_addr.s_addr), sizeof(in_addr_t));
                //read(clientSocket, &(peerAddress.sin_port), sizeof(in_port_t));

                // Connect to peer
                if ((peerSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
                    perror(RED("[ERROR]")" Socket creation failed\n");
                    exit(EXIT_FAILURE);
                }
                if (connect(peerSocket, (struct sockaddr*)&peerAddress, addrlen) < 0) {
                    printf(RED("Peer offline :(\n"));
                    peerSocket = -1;
                    continue;
                }

                pthread_mutex_lock(&mutex);
                DMOngoing = true;
                pthread_mutex_unlock(&mutex);

                // Wait for peer response
                sendMessage(peerSocket, "CHAT");
                sendMessage(peerSocket, currentUserID); // Send messaging request
                char response[3];
                printf(YELLOW("Waiting for peer to repond, please wait(10s)...")"\n");
                readMessage(peerSocket, response);

                if (strcmp(response, "no") == 0) { // Request timed out
                    printf(YELLOW("Peer did not accept DM request :(\n"));
                    pthread_mutex_lock(&mutex);
                    DMOngoing = false;
                    pthread_mutex_unlock(&mutex);
                    continue;
                } else if (strcmp(response, "nob") == 0) { // Peer in another chat session already
                    printf(YELLOW("Peer busy, please try again later.\n"));
                    pthread_mutex_lock(&mutex);
                    DMOngoing = false;
                    pthread_mutex_unlock(&mutex);
                    continue;
                }

                // Send RSA public key
                sendMessage(peerSocket, my_asym_public_key);
                unsigned char encrypt_text[KEYBYTES] = {0};
                int r = read(peerSocket, encrypt_text, KEYBYTES);
//                printf("encrypt_text(%d):\n", r);
//                for (int i = 0; i<r; ++i) printf("%02x", encrypt_text[i]);
//                printf("\n");
                int chat_sym_key_len;
                rsa_decrypt_key(asym_key, encrypt_text, (size_t)r, chat_sym_key, &chat_sym_key_len);
                sendencryptMessage(peerSocket,"receive key", sym_key);

                // Start chat session
                printf(YELLOW("Entering chat...\n"));
                strcpy(currentPeerID, inputTokens[1]);
                oneToOneChat();
                printf(YELLOW("...chat with ")BLUE("%s")YELLOW(" ended\n"), currentPeerID);
                close(peerSocket);
                peerSocket = -1;
                currentPeerID[0] = '\0';

                pthread_mutex_lock(&mutex);
                DMOngoing = false;
                pthread_mutex_unlock(&mutex);

            } else {
                printf("Invalid parameters.\nUsage: chat <ID>\n");
            }

//MARK: - Sendfile
        } else if (strcmp(token, "sendfile") == 0) {
            char sendBuffer[BUFFERSIZE] = "";
            char inputTokens[3][BUFFERSIZE] = {0}; // 1 peerID, 2 filepath
            int parameterIndex = parseInput(token, sendBuffer, inputTokens);
            if (parameterIndex == 3) {
                if (!loggedIn) {
                    printf("You are currently not logged in, plaese login to use this feature.\n");
                } else if (strcmp(inputTokens[1], currentUserID) == 0) {
                    printf("Cannot send a file to yourself.\n");
                } else {
                    // Ask server for peer address (reuse chat <ID> flow)
                    char addrReq[BUFFERSIZE] = "";
                    snprintf(addrReq, sizeof(addrReq), "chat %s", inputTokens[1]);
                    sendencryptMessage(clientSocket, addrReq, sym_key);
                    readencryptMessage(clientSocket, recvBuffer, sym_key);
                    if (strncmp((char*)recvBuffer, "Peer", 4) == 0) {
                        printf("%s", recvBuffer);
                    } else {
                        struct sockaddr_in peerAddress; socklen_t addrlen = sizeof(peerAddress);
                        peerAddress.sin_family = AF_INET;
                        unsigned char str_addr[5] = {}, str_port[3] = {};
                        readencryptMessage(clientSocket, str_addr, sym_key);
                        readencryptMessage(clientSocket, str_port, sym_key);
                        memcpy(&(peerAddress.sin_addr.s_addr), str_addr, sizeof(in_addr_t));
                        memcpy(&(peerAddress.sin_port), str_port, sizeof(in_port_t));
                        int fsock = socket(AF_INET, SOCK_STREAM, 0);
                        if (fsock < 0) { perror(RED("[ERROR]")" Socket creation failed\n"); }
                        else if (connect(fsock, (struct sockaddr*)&peerAddress, addrlen) < 0) {
                            printf(RED("Peer offline :(\n"));
                            close(fsock);
                        } else {
                            // Extract basename of file path
                            const char *fullpath = inputTokens[2];
                            const char *slash = strrchr(fullpath, '/');
                            const char *basename = slash ? (slash + 1) : fullpath;
                            // Get file size
                            FILE *fp = fopen(fullpath, "rb");
                            if (!fp) {
                                perror(RED("[ERROR]")" Cannot open file\n");
                                shutdown(fsock, SHUT_WR); close(fsock);
                            } else {
                                // Identify this connection as a file transfer and send metadata
                                sendMessage(fsock, "FILE");
                                sendMessage(fsock, currentUserID);
                                sendMessage(fsock, (char*)basename);
                                
                                fseeko(fp, 0, SEEK_END); off_t fsz = ftello(fp); fseeko(fp, 0, SEEK_SET);
                                char sizeStr[64]; snprintf(sizeStr, sizeof(sizeStr), "%lld", (long long)fsz);
                                sendMessage(fsock, sizeStr);
                                
                                // Wait for receiver acceptance before proceeding
                                printf(YELLOW("Waiting for peer to accept file transfer...(10s)\n"));
                                char fileAcceptResp[16] = {0};
                                readMessage(fsock, fileAcceptResp);
                                if (strcmp(fileAcceptResp, "FILE_OK") != 0) {
                                    printf(YELLOW("Peer did not accept file transfer.\n"));
                                    fclose(fp);
                                    shutdown(fsock, SHUT_WR); close(fsock);
                                    continue;
                                }
                                
                                // Perform key exchange: send RSA public key and receive encrypted symmetric key
                                sendMessage(fsock, (char*)my_asym_public_key);
                                unsigned char encrypt_text[KEYBYTES] = {0};
                                int rbytes = (int)read(fsock, encrypt_text, KEYBYTES);
                                int file_sym_len = 0;
                                rsa_decrypt_key(asym_key, encrypt_text, (size_t)rbytes, file_sym_key, &file_sym_len);
                                // Acknowledge (encrypted) to ensure both sides are ready
                                sendencryptMessage(fsock, "FILE_KEY_OK", file_sym_key);

                                long long sentTotal = 0;

                                // Simple base64 encode inline
                                static const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                                const size_t CHUNK = 512; // keep small so encoded+overhead fits BUFFERSIZE
                                unsigned char raw[CHUNK];
                                char b64buf[BUFFERSIZE];
                                size_t nread;
                                while ((nread = fread(raw, 1, CHUNK, fp)) > 0) {
                                    // Base64 encode raw -> b64buf
                                    static const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                                    size_t j = 0; size_t i = 0;
                                    unsigned char a3[3];
                                    for (size_t inpos = 0; inpos < nread; ) {
                                        i = 0;
                                        while (i < 3 && inpos < nread) {
                                            a3[i++] = raw[inpos++];
                                        }
                                        if (i == 3) {
                                            b64buf[j++] = b64chars[(a3[0] & 0xfc) >> 2];
                                            b64buf[j++] = b64chars[((a3[0] & 0x03) << 4) | ((a3[1] & 0xf0) >> 4)];
                                            b64buf[j++] = b64chars[((a3[1] & 0x0f) << 2) | ((a3[2] & 0xc0) >> 6)];
                                            b64buf[j++] = b64chars[a3[2] & 0x3f];
                                        } else if (i == 2) {
                                            b64buf[j++] = b64chars[(a3[0] & 0xfc) >> 2];
                                            b64buf[j++] = b64chars[((a3[0] & 0x03) << 4) | ((a3[1] & 0xf0) >> 4)];
                                            b64buf[j++] = b64chars[(a3[1] & 0x0f) << 2];
                                            b64buf[j++] = '=';
                                        } else if (i == 1) {
                                            b64buf[j++] = b64chars[(a3[0] & 0xfc) >> 2];
                                            b64buf[j++] = b64chars[(a3[0] & 0x03) << 4];
                                            b64buf[j++] = '=';
                                            b64buf[j++] = '=';
                                        }
                                    }
                                    b64buf[j] = '\0';

                                    sendencryptMessage(fsock, b64buf, file_sym_key);

                                    sentTotal += (long long)nread;
                                    double spct = (fsz > 0) ? (100.0 * (double)sentTotal / (double)fsz) : 0.0;
                                    printf("\rSending %s: %lld/%lld bytes (%.0f%%)", basename, sentTotal, (long long)fsz, spct);
                                    fflush(stdout);
                                }
                                fclose(fp);
                                printf("\n");
                                // Signal end of file
                                sendencryptMessage(fsock, "FILE_END", file_sym_key);
                                shutdown(fsock, SHUT_WR); close(fsock);
                                printf(GREEN("File sent successfully.\n"));
                            }
                        }
                    }
                }
            } else {
                printf("Invalid parameters.\nUsage: sendfile <ID> <filepath>\n");
            }

//MARK: - Accept DM
        } else if (strcmp(token, "accept") == 0){
            if (!loggedIn) {
                printf("You are currently not logged in, plaese login to use this feature.\n");
                continue;
            }
            if (!pendingRequest) {
                printf(YELLOW("No incoming message requests now.\n"));
                continue;
            }
            if (DMOngoing) {
                printf(RED("Cannot have more than one ongoing chat at once.\n"));
                continue;
            }

            // Notify acceptDM thread ready to accpet next incoming request
            pthread_mutex_lock(&mutex);
            DMOngoing = true;
            acceptSignal = true;
            pthread_cond_signal(&readyToAccept);
            pthread_mutex_unlock(&mutex);

            // Accept DM request
            sendMessage(peerSocket, "yes");

            // create symmetric key
            RAND_bytes(chat_sym_key, sizeof(chat_sym_key));
            exchange_key(chat_sym_key, peerSocket);

            // Start chat session
            printf(YELLOW("Entering chat...\n"));
            oneToOneChat();
            printf(YELLOW("...chat with ")BLUE("%s")YELLOW(" ended\n"), currentPeerID);
            close(peerSocket);
            peerSocket = -1;
            currentPeerID[0] = '\0';

            pthread_mutex_lock(&mutex);
            DMOngoing = false;
            pthread_mutex_unlock(&mutex);

//MARK: - Accept File
        } else if (strcmp(token, "acceptfile") == 0) {
            if (!loggedIn) {
                printf("You are currently not logged in, plaese login to use this feature.\n");
                continue;
            }
            pthread_mutex_lock(&mutex);
            if (!filePendingRequest || fileSocket < 0) {
                pthread_mutex_unlock(&mutex);
                printf(YELLOW("No incoming file requests now.\n"));
                continue;
            }
            fileAcceptSignal = true;
            pthread_cond_signal(&readyToAcceptFile);
            pthread_mutex_unlock(&mutex);

//MARK: - Help
        } else if (strcmp(token, "help") == 0) {
            printf(YELLOW("%-25s")": %-25s\n", "Registration", "register <ID> <password>");
            printf(YELLOW("%-25s")": %-25s\n", "Deregistration", "deregister <ID> <password>");
            printf(YELLOW("%-25s")": %-25s\n", "Login", "login <ID> <password>");
            printf(YELLOW("%-25s")": %-25s\n", "Logout", "logout");
            printf(YELLOW("%-25s")": %-25s\n", "List Online Users", "list");
            printf(YELLOW("%-25s")": %-25s\n", "Chat with user", "chat <ID>");
            printf(YELLOW("%-25s")": %-25s\n", "Accept chat request", "accept");
            printf(YELLOW("%-25s")": %-25s\n", "Send file to user", "sendfile <ID> <filepath>");
            printf(YELLOW("%-25s")": %-25s\n", "Accept file request", "acceptfile");
            printf(YELLOW("%-25s")": %-25s\n", "Exit Client Program", "exit");
        } else {
            printf("Unknown command, type \"help\" for usage.\n");
        }
    }

    pthread_cancel(DMAcceptor);
    pthread_join(DMAcceptor, NULL);

    pthread_mutex_destroy(&mutex);
    pthread_mutex_destroy(&drawWindow);
    pthread_cond_destroy(&readyToAccept);
    pthread_cond_destroy(&readyToAcceptFile);

    return 0;
}

//MARK: - DM Logic
static void *acceptDM(void *arg) { // Thread function to constantly listen for peer chat requests
    int tmp, listeningSocket = *(int *)arg;
    struct sockaddr_in address; // IP and port number to bind the socket to
    socklen_t addrlen = sizeof(address); // length of address

    while (true) {
        // Accept new connection
        if ((tmp = accept(listeningSocket, (struct sockaddr*)&address, &addrlen)) < 0) {
            fprintf(stderr, RED("[ERROR]")" Accepting connection failed\n");
            continue;
        }

        char typeTag[16] = {0};
        readMessage(tmp, typeTag);
        if (strcmp(typeTag, "CHAT") == 0) {
            pthread_mutex_lock(&mutex);
            if (DMOngoing) {
                // consume the sender's next message (their ID)
                readMessage(tmp, currentPeerID);
                sendMessage(tmp, "nob");
                shutdown(tmp, SHUT_WR);
                close(tmp);
                currentPeerID[0] = '\0';
                pthread_mutex_unlock(&mutex);
                continue;
            }
            pthread_mutex_unlock(&mutex);
            peerSocket = tmp; // assign the accepted socket to the global for chat

            // Read peer ID and prompt user to accept via "accept" command
            readMessage(peerSocket, currentPeerID);
            printf("\n"YELLOW("[INCOMING]")BLUE(" %s")" wants to chat, accept? [accept](10s)\n", currentPeerID);
            printf(BOLD("%s> "), currentUserID);
            fflush(stdout);

            pthread_mutex_lock(&mutex);
            pendingRequest = true;

            // Compute wake-up time (10 seconds from now)
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += 10;

            // Wait for accept or timeout
            while (!acceptSignal) {
                int ret = pthread_cond_timedwait(&readyToAccept, &mutex, &ts);
                if (ret == ETIMEDOUT) {
                    sendMessage(peerSocket, "no");
                    shutdown(peerSocket, SHUT_WR);
                    close(peerSocket);
                    currentPeerID[0] = '\0';
                    peerSocket = -1;
                    break;
                }
            }

            acceptSignal = false;
            pendingRequest = false;
            pthread_mutex_unlock(&mutex);

        } else if (strcmp(typeTag, "FILE") == 0) {
            int fileSock = tmp;
            char senderID[BUFFERSIZE] = {0};
            char filename[BUFFERSIZE] = {0};
            char sizeStr[64] = {0};
            readMessage(fileSock, senderID);
            readMessage(fileSock, filename);
            readMessage(fileSock, sizeStr);
            long long expectedSize = atoll(sizeStr);

            // Prompt for file acceptance
            printf("\n"YELLOW("[INCOMING FILE]")BLUE(" %s")" -> %s (%s bytes). Accept? [acceptfile](10s)\n", senderID, filename, sizeStr);
            printf(BOLD("%s> "), currentUserID);
            fflush(stdout);

            pthread_mutex_lock(&mutex);
            filePendingRequest = true;
            fileSocket = fileSock;
            strncpy(incomingFileSender, senderID, sizeof(incomingFileSender) - 1);
            strncpy(incomingFileName, filename, sizeof(incomingFileName) - 1);
            incomingFileSize = expectedSize;
            struct timespec tsf; clock_gettime(CLOCK_REALTIME, &tsf); tsf.tv_sec += 10;
            while (!fileAcceptSignal) {
                int retf = pthread_cond_timedwait(&readyToAcceptFile, &mutex, &tsf);
                if (retf == ETIMEDOUT) {
                    // timeout: notify sender and close
                    sendMessage(fileSocket, "FILE_NO");
                    close(fileSocket);
                    fileSocket = -1;
//                    filePendingRequest = false;
//                    fileAcceptSignal = false;
//                    pthread_mutex_unlock(&mutex);
                    // continue outer accept loop
                    break;
                }
            }
            fileAcceptSignal = false;
            filePendingRequest = false;
            pthread_mutex_unlock(&mutex);

            // Inform sender that we accept and are ready to exchange keys
            sendMessage(fileSock, "FILE_OK");

            // Acknowledge and perform symmetric key exchange
            RAND_bytes(file_sym_key, (int)sizeof(file_sym_key));
            exchange_key(file_sym_key, fileSock);

            // Ensure downloads directory exists
            mkdir("downloads", 0700);
            char outPath[BUFFERSIZE * 2];
            snprintf(outPath, sizeof(outPath), "downloads/%s", filename);
            FILE *out = fopen(outPath, "wb");
            if (!out) {
                perror(RED("[ERROR]")" Cannot open output file\n");
                shutdown(fileSock, SHUT_WR); close(fileSock);
                pthread_testcancel();
                continue;
            }

//            // Wait for sender's key-ready ack
//            unsigned char ackBuf[BUFFERSIZE] = {0};
//            readencryptMessage(fileSock, ackBuf, file_sym_key);

            // Receive file chunks until FILE_END
            long long receivedTotal = 0;
            unsigned char encBuf[BUFFERSIZE] = {0};
            while (1) {
                memcpy(encBuf, 0, BUFFERSIZE);
                readencryptMessage(fileSock, encBuf, file_sym_key);
                if (strcmp((char*)encBuf, "FILE_END") == 0) break;
                // Base64 decode encBuf -> decoded[] and write
                const char *p = (const char*)encBuf;
                size_t len = strlen(p);
                unsigned char decoded[BUFFERSIZE];
                size_t decLen = 0;
                int val = 0, valb = -8;
                for (size_t i = 0; i < len; i++) {
                    unsigned char c = (unsigned char)p[i];
                    int d = -1;
                    if (c >= 'A' && c <= 'Z') d = c - 'A';
                    else if (c >= 'a' && c <= 'z') d = c - 'a' + 26;
                    else if (c >= '0' && c <= '9') d = c - '0' + 52;
                    else if (c == '+') d = 62;
                    else if (c == '/') d = 63;
                    else if (c == '=') { break; }
                    else { continue; }
                    val = (val << 6) | d;
                    valb += 6;
                    if (valb >= 0) {
                        decoded[decLen++] = (unsigned char)((val >> valb) & 0xFF);
                        valb -= 8;
                        if (decLen == sizeof(decoded)) {
                            fwrite(decoded, 1, decLen, out);
                            receivedTotal += decLen;
                            decLen = 0;
                        }
                    }
                }
                if (decLen > 0) {
                    fwrite(decoded, 1, decLen, out);
                    receivedTotal += decLen;
                }
                if (incomingFileSize > 0) {
                    double rpct = (100.0 * (double)receivedTotal / (double)incomingFileSize);
                    printf("\rReceiving %s: %lld/%lld bytes (%.0f%%)", incomingFileName, receivedTotal, incomingFileSize, rpct);
                    fflush(stdout);
                }
            }
            printf("\n");
            fclose(out);
            shutdown(fileSock, SHUT_WR); close(fileSock);
            printf(GREEN("Received file saved to %s (%lld bytes).\n"), outPath, receivedTotal);
            printf(BOLD("%s> "), currentUserID);
            fflush(stdout);

            // Continue loop to accept more connections
            continue;
        } else {
            // Unknown type, close
            shutdown(tmp, SHUT_WR); close(tmp);
            continue;
        }

        pthread_testcancel();
    }

    return NULL;
}

#define MAXMESSAGES 100
#define MAXMSGLEN 1024
char messageBuffer[MAXMESSAGES][MAXMSGLEN + TIMEWINDOWWIDTH + 1]; // Buffer to store last 100 messages, message | timestamp | 0 self/1 peer X 0 message/1 ID tag
char chatInputBuffer[BUFFERSIZE] = ""; // buffer for user input
char prevTimestamp[TIMEWINDOWWIDTH] ; // Store previous time stamp
int messageCount = 0, oldestMessage = 0; // Number of messages, index of oldest message
int pos = 0; // Tracks cursor position as user inputs characters
WINDOW *messageWindow, *inputWindow, *statusWindow, *timeWindow;

static void oneToOneChat(void) {
    // UI setup
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    start_color(); // Enable color functionality
    use_default_colors(); // Optional: allow transparency with terminal default background

    init_pair(1, COLOR_RED, -1); // Red text on default background
    init_pair(2, COLOR_BLUE, -1); // Blue text on default background
    init_pair(3, COLOR_YELLOW, -1); // Yellow text on default background

    int cols = getmaxx(stdscr);
    resizeWindows(); // Create windows

    // Create message reciever thread for chat
    if (pthread_create(&messageReciever, NULL, recvMessage, NULL) != 0) {
        perror(RED("[ERROR]")" Failed to create message reciever thread\n");
        endwin();
        exit(EXIT_FAILURE);
    }
    // Set up resize handler
    signal(SIGWINCH, handleWindowResize);
    int inputCharacter;
    char timestamp[TIMEWINDOWWIDTH];
    time_t now = time(NULL) - 60; // -60 to trigger the first message
    struct tm *t = localtime(&now);
    strftime(prevTimestamp, sizeof(prevTimestamp), "%a %b %d %H:%M", t);

    // Keep reading user input and send them
    while (true) {
        inputCharacter = wgetch(inputWindow);
        if (inputCharacter == 27) { // ESC key, end chat session
            break;
        } else if (peerSocket < 0) { // Peer has left
            continue;
        } else if (inputCharacter == '\n') { // Input with \n as ending
            if (pos > 0) { // User has input something
                chatInputBuffer[pos] = '\0';

                // Display & send message
                sendencryptMessage(peerSocket, chatInputBuffer, chat_sym_key);
                pthread_mutex_lock(&drawWindow);
                // Print sender
                wattron(messageWindow, COLOR_PAIR(1));
                if (strcmp(lastMessageSentBy, currentUserID) != 0) { // Last message not sent by current user, print sender
                    wprintw(messageWindow, "%s:\n", currentUserID);
                    wprintw(timeWindow, "\n");
                    strcpy(lastMessageSentBy, currentUserID);
                    strcpy(messageBuffer[messageCount], currentUserID); // Store ID tag
                    strcpy(messageBuffer[messageCount] + MAXMSGLEN, "\n"); // Store timestamp
                    messageBuffer[messageCount][MAXMSGLEN + TIMEWINDOWWIDTH] = 1; // 01 self tag
                    messageCount++;
                    messageCount %= MAXMESSAGES;
                    if (messageCount == oldestMessage) {
                        oldestMessage++;
                        oldestMessage %= MAXMESSAGES;
                    }
                }

                // Print message
                wprintw(messageWindow, " > %s\n", chatInputBuffer);
                wattroff(messageWindow, COLOR_PAIR(1));

                // Print timestamp
                now = time(NULL);
                t = localtime(&now);
                strftime(timestamp, sizeof(timestamp), "%a %b %d %H:%M", t);
                if (strcmp(prevTimestamp, timestamp) != 0) {
                    wprintw(timeWindow, " %s\n", timestamp);
                    strcpy(prevTimestamp, timestamp);
                    strcpy(messageBuffer[messageCount] + MAXMSGLEN, timestamp);
                } else {
                    wprintw(timeWindow, "\n");
                    strcpy(messageBuffer[messageCount] + MAXMSGLEN, "\n");
                }
                for (int i = 0; i < pos / (cols - TIMEWINDOWWIDTH - 3); i++) {
                    wprintw(timeWindow, "\n");
                }
                // Update message history
                strcpy(messageBuffer[messageCount], chatInputBuffer);
                messageBuffer[messageCount][MAXMSGLEN + TIMEWINDOWWIDTH] = 0; // 00 self message
                messageCount++;
                messageCount %= MAXMESSAGES;
                if (messageCount == oldestMessage) {
                    oldestMessage++;
                    oldestMessage %= MAXMESSAGES;
                }
                wrefresh(timeWindow);
                wrefresh(messageWindow);
                pthread_mutex_unlock(&drawWindow);

                pos = 0;
                memset(chatInputBuffer, 0, sizeof(chatInputBuffer));
            }
        } else if (inputCharacter == KEY_BACKSPACE || inputCharacter == 127) { // Backspace
            if (pos > 0) {
                chatInputBuffer[--pos] = '\0';
            }
        } else if (isprint(inputCharacter) && pos < BUFFERSIZE - 1) {
            chatInputBuffer[pos++] = inputCharacter;
        }

        // Draw Status bar
        pthread_mutex_lock(&drawWindow);
        werase(statusWindow);
        mvwprintw(statusWindow, 0, 0, " Chatting with %s | Press ESC to leave ", currentPeerID);
        wrefresh(statusWindow);
        pthread_mutex_unlock(&drawWindow);

        // Draw input field
        pthread_mutex_lock(&drawWindow);
        werase(inputWindow);
        wattron(inputWindow, COLOR_PAIR(1));
        mvwprintw(inputWindow, 0, 0, "%s> %s", currentUserID, chatInputBuffer);
        wattroff(inputWindow, COLOR_PAIR(1));
        wrefresh(inputWindow);
        pthread_mutex_unlock(&drawWindow);
    }

    if (peerSocket > 0) { // Initiate termination from this side
        sendencryptMessage(peerSocket, "CLOSEDM", chat_sym_key);
    }

    // Cancel the message recieving thread
    pthread_cancel(messageReciever);
    pthread_join(messageReciever, NULL);
    endwin();
    return;
}

static void *recvMessage(void *arg) {
    char recvBuffer[BUFFERSIZE] = ""; // buffer for messages from peer
    char timestamp[TIMEWINDOWWIDTH];
    time_t now = time(NULL) - 60; // -60 to trigger the first message
    struct tm *t = localtime(&now);
    strftime(prevTimestamp, sizeof(prevTimestamp), "%a %b %d %H:%M", t);
    int messageWindowWidth = getmaxx(messageWindow);
    while (true) {
        readencryptMessage(peerSocket, recvBuffer, chat_sym_key);

        if (strcmp(recvBuffer, "CLOSEDM") == 0) {
            close(peerSocket);
            peerSocket = -1;

            pthread_mutex_lock(&drawWindow);
            wattron(messageWindow, COLOR_PAIR(3));
            wprintw(messageWindow, "Peer left the chat. (Hit ESC to continue)\n");
            wattroff(messageWindow, COLOR_PAIR(3));
            wrefresh(messageWindow);
            wrefresh(inputWindow);
            pthread_mutex_unlock(&drawWindow);
            break;
        } else {
            pthread_mutex_lock(&drawWindow);
            // Print sender
            wattron(messageWindow, COLOR_PAIR(2));
            if (strcmp(lastMessageSentBy, currentPeerID) != 0) { // Last message not sent by peer, print sender
                wprintw(messageWindow, "%s:\n", currentPeerID);
                wprintw(timeWindow, "\n");
                strcpy(lastMessageSentBy, currentPeerID);
                strcpy(messageBuffer[messageCount], currentPeerID); // Store ID tag
                strcpy(messageBuffer[messageCount] + MAXMSGLEN, "\n"); // Store timestamp
                messageBuffer[messageCount][MAXMSGLEN + TIMEWINDOWWIDTH] = 3; // 11 peer ID tag
                messageCount++;
                messageCount %= MAXMESSAGES;
                if (messageCount == oldestMessage) {
                    oldestMessage++;
                    oldestMessage %= MAXMESSAGES;
                }
            }

            // Print message
            wprintw(messageWindow, " > %s\n", recvBuffer);
            wattroff(messageWindow, COLOR_PAIR(2));

            // Print timestamp
            now = time(NULL);
            t = localtime(&now);
            strftime(timestamp, sizeof(timestamp), "%a %b %d %H:%M", t);
            if (strcmp(prevTimestamp, timestamp) != 0) {
                wprintw(timeWindow, " %s\n", timestamp);
                strcpy(prevTimestamp, timestamp);
                strcpy(messageBuffer[messageCount] + MAXMSGLEN, timestamp);
            } else {
                wprintw(timeWindow, "\n");
                strcpy(messageBuffer[messageCount] + MAXMSGLEN, "\n");
            }
            for (int i = 0; i < strlen(recvBuffer) / (messageWindowWidth - 3); i++) {
                wprintw(timeWindow, "\n");
            }
            // Update message history
            strcpy(messageBuffer[messageCount], recvBuffer);
            messageBuffer[messageCount][MAXMSGLEN + TIMEWINDOWWIDTH] = 2; // 10 peer message
            messageCount++;
            messageCount %= MAXMESSAGES;
            if (messageCount == oldestMessage) {
                oldestMessage++;
                oldestMessage %= MAXMESSAGES;
            }
            wrefresh(timeWindow);
            wrefresh(messageWindow);
            wrefresh(inputWindow);
            pthread_mutex_unlock(&drawWindow);
        }

        pthread_testcancel();
    }
    return NULL;
}

//MARK: - Helper Functions
static int connectToServer(int clientSocket) {
    struct sockaddr_in serverAddress; // IP and port number to bind the socket to
    socklen_t addrlen = sizeof(serverAddress); // length of address

    // Create socket file descriptor
    if ((clientSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror(RED("Socket creation failed\n"));
        exit(EXIT_FAILURE);
    }

    serverAddress.sin_family = AF_INET; // address family is IPv4
    serverAddress.sin_port = htons(SERVERPORT); // set port number

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &serverAddress.sin_addr) <= 0) {
        perror(RED("Invalid address/ Address not supported\n"));
        exit(EXIT_FAILURE);
    }

    // Connect to server
    if (connect(clientSocket, (struct sockaddr*)&serverAddress, addrlen) < 0) {
        perror(RED("Connection to server failed\n"));
        //exit(EXIT_FAILURE);
        clientSocket = -1;
    }

    return clientSocket;
}

static int setListeningSocket(int listeningSocket, int listeningPort) {
    struct sockaddr_in address; // IP and port number to bind the socket to
    socklen_t addrlen = sizeof(address); // length of address

    // Create socket file descriptor, use IPv4 and TCP
    if ((listeningSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror(RED("Socket creation failed\n"));
        exit(EXIT_FAILURE);
    }
    // Attach serverSocket to the port 12000
    int opt = 1;
    if (setsockopt(listeningSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror(RED("Set socket options failed\n"));
        exit(EXIT_FAILURE);
    }
    if (setsockopt(listeningSocket, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt))) {
        perror(RED("Set socket options failed\n"));
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET; // address family is IPv4
    address.sin_addr.s_addr = INADDR_ANY; // socket will be bound to all local interfaces
    address.sin_port = htons(listeningPort); // set port number
    if (bind(listeningSocket, (struct sockaddr*)&address, addrlen) < 0) {
        perror(RED("Binding socket to port failed\n"));
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    int maxWaitingToConnect = 0;
    if (listen(listeningSocket, maxWaitingToConnect) < 0) {
        perror(RED("[ERROR]")" Listening for connection failed\n");
        exit(EXIT_FAILURE);
    }

    return listeningSocket;
}

static int sendMessage(int socket, char *buffer) {
    int32_t messageLength = htonl(strlen(buffer) + 1);
    if (send(socket, &messageLength, sizeof(messageLength), 0) < 0) {
        return -1;
    }
    send(socket, buffer, strlen(buffer) + 1, 0);
    return 0;
}

static int readMessage(int socket, char *buffer) {
    int32_t messageLength;
    read(socket, &messageLength, sizeof(messageLength));
    int r = read(socket, buffer, ntohl(messageLength));
    return r;
}

static int parseInput(char *token, char *buffer, char (*input)[BUFFERSIZE]){
    int parameterIndex = 0;
    while (token != NULL) {
        if (parameterIndex >= 4) {
            break;
        }
        if (input != NULL) {
            strcpy(input[parameterIndex], token);
        }
        strcat(buffer, token);
        strcat(buffer, " ");
        token = strtok(NULL, " ");
        parameterIndex++;
    } // rebuild user input
    return parameterIndex;
}

static int setListeningPort(int argc, const char **argv) {
    if (argc != 2) {
        printf(RED("Usage: ./client.out <Listening port number>\n"));
        exit(-1);
    }

    int listeningPort = atoi(argv[1]); // socket fd
    if (listeningPort < 49152 || listeningPort > 65535) {
        printf(RED("Invalid port number, please choose in the range of [49152, 65535]\n"));
        exit(-1);
    }
    return listeningPort;
}

//MARK: - UI Update Logic
static void handleWindowResize(int sig) {
    endwin();
    refresh();
    clear();
    resizeWindows();
    return;
}

static void resizeWindows(void) {
    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    // Delete old windows if they exist
    if (messageWindow) delwin(messageWindow);
    if (statusWindow) delwin(statusWindow);
    if (inputWindow) delwin(inputWindow);
    if (timeWindow) delwin(timeWindow);

    // Create windows
    messageWindow = newwin(rows - 2, cols - TIMEWINDOWWIDTH, 0, 0); // Rows 0 ~ (rows - 3), Columns 0 ~ (cols - 21)
    timeWindow = newwin(rows - 2, TIMEWINDOWWIDTH, 0, cols - TIMEWINDOWWIDTH);
    inputWindow = newwin(1, cols, rows - 1, 0);
    statusWindow = newwin(1, cols, rows - 2, 0);
    wbkgd(statusWindow, A_REVERSE | COLOR_PAIR(3));
    wbkgd(timeWindow, A_DIM);
    scrollok(messageWindow, TRUE);
    idlok(messageWindow, TRUE);
    scrollok(timeWindow, TRUE);
    idlok(timeWindow, TRUE);
    scrollok(inputWindow, TRUE);
    idlok(inputWindow, TRUE);

    // Draw message area
    pthread_mutex_lock(&drawWindow);
    werase(messageWindow);
    int messageWindowHeight, messageWindowWidth;
    getmaxyx(messageWindow, messageWindowHeight, messageWindowWidth);
    int startIndex = (messageCount > messageWindowHeight)? (messageCount - messageWindowHeight) % MAXMESSAGES : oldestMessage;
    int linesToPrint = (messageCount > messageWindowHeight)? messageWindowHeight : messageCount;
    for (int i = 0; i < linesToPrint; i++) {
        if (messageBuffer[(startIndex + i) % MAXMESSAGES][MAXMSGLEN + TIMEWINDOWWIDTH] < 2) { // Self 0x
            wattron(messageWindow, COLOR_PAIR(1));
        } else { // Peer 1x
            wattron(messageWindow, COLOR_PAIR(2));
        }
        if (messageBuffer[(startIndex + i) % MAXMESSAGES][MAXMSGLEN + TIMEWINDOWWIDTH] % 2 == 0) { // Message x0
            wprintw(messageWindow, " > %s\n", messageBuffer[(startIndex + i) % MAXMESSAGES]);
        } else { // ID tag x1
            wprintw(messageWindow, "%s:\n", messageBuffer[(startIndex + i) % MAXMESSAGES]);
        }
        if (messageBuffer[(startIndex + i) % MAXMESSAGES][MAXMSGLEN + TIMEWINDOWWIDTH] < 2) { // Self 0x
            wattroff(messageWindow, COLOR_PAIR(1));
        } else { // Peer 1x
            wattroff(messageWindow, COLOR_PAIR(2));
        }
    }
    wrefresh(messageWindow);

    // Draw timestamp area
    werase(timeWindow);
    for (int i = startIndex; i < linesToPrint; i++) {
        wprintw(timeWindow, " %s\n", messageBuffer[(startIndex + i) % MAXMESSAGES] + MAXMSGLEN);
        for (int j = 0; j < strlen(messageBuffer[(startIndex + i) % MAXMESSAGES]) / (messageWindowWidth - 3); j++) {
            wprintw(timeWindow, "\n");
        }
    }
    wrefresh(timeWindow);

    // Draw status bar
    werase(statusWindow);
    mvwprintw(statusWindow, 0, 0, " Chatting with %s | Press ESC to leave ", currentPeerID);
    wrefresh(statusWindow);

    // Prepare input window
    werase(inputWindow);
    wattron(inputWindow, COLOR_PAIR(1));
    mvwprintw(inputWindow, 0, 0, "%s> %s", currentUserID, chatInputBuffer);
    wattroff(inputWindow, COLOR_PAIR(1));
    curs_set(1); // Show cursor
    wmove(inputWindow, 0, pos + 2 + (int)strlen(currentUserID)); // Move cursor to inputWindow
    wrefresh(inputWindow);
    pthread_mutex_unlock(&drawWindow);
    return;
}

