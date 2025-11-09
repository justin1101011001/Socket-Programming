#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>

#include "client.h"

#define SERVERPORT 12014
#define BUFFERSIZE 1024

static pthread_t messageReciever;
static pthread_t DMAcceptor;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t readyToAccept = PTHREAD_COND_INITIALIZER;

bool acceptSignal = false; // DM request accpeted
bool DMOngoing = false; // Flag indicating if there's an ongoing DM session
bool pendingRequest = false;

char currentUserID[100] = "";
char currentPeerID[100] = "";

int peerSocket; // Used for DM

int main(int argc, char const* argv[]) {
//MARK: - Socket Setup
    int listeningPort = setListeingPort(argc, argv); // Get listening port from arguments
    int listeningSocket = 0, clientSocket = 0;
    listeningSocket = setListeningSocket(listeningSocket, listeningPort); // Set listening socket

    char recvBuffer[BUFFERSIZE] = {0}; // buffer for messages from server
    char inputBuffer[BUFFERSIZE] = {0}; // buffer for user input
    bool loggedIn = false; // is the user currently logged in
    
    if (pthread_create(&DMAcceptor, NULL, acceptDM, &listeningSocket) != 0) {
        perror(RED("[ERROR]")" Failed to create DM acceptor thread\n");
        exit(EXIT_FAILURE);
    }
    
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
                sendMessage(clientSocket, token);
                readMessage(clientSocket, recvBuffer);
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
            
            sendMessage(clientSocket, token);
            readMessage(clientSocket, recvBuffer);
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
                sendMessage(clientSocket, sendBuffer);
                readMessage(clientSocket, recvBuffer);
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
                sendMessage(clientSocket, sendBuffer); // Send deregistration request
                readMessage(clientSocket, recvBuffer); // Read comfirmation message
                printf("%s", recvBuffer);
                
                if (strncmp(recvBuffer, "You", 3) == 0) { // Password check passed
                    // User input to confirm deregistration
                    printf(BOLD("%s> "), currentUserID);
                    fgets(inputBuffer, BUFFERSIZE, stdin); // read whole line of input
                    inputBuffer[strcspn(inputBuffer, "\n")] = '\0'; // trim off the newline character at the end
                    sendMessage(clientSocket, inputBuffer); // Send comfirmation
                    readMessage(clientSocket, recvBuffer); // Server response
                    
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
                sendMessage(clientSocket, sendBuffer);
                readMessage(clientSocket, recvBuffer);
                
                if (strncmp(recvBuffer, "OK.", 3) == 0) { // if successfully logged in
                    int32_t formatted = htons(listeningPort);
                    send(clientSocket, &formatted, sizeof(int32_t), 0);
                    loggedIn = true;
                    
                    strcpy(currentUserID, inputTokens[1]); // Add logged in user name to prompt
                    readMessage(clientSocket, recvBuffer);
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
            
            sendMessage(clientSocket, token);
            readMessage(clientSocket, recvBuffer);
            printf(GREEN("Online Users\n====================\n"));
            while (strcmp(recvBuffer, "END OF USER LIST") != 0) {
                printf(GREEN("%s\n"), recvBuffer);
                readMessage(clientSocket, recvBuffer);
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
                    printf("???\n");
                    continue;
                }
                if (DMOngoing) {
                    printf(RED("Cannot have more than one ongoing chat at once.\n"));
                    continue;
                }
                
                // Get peer address from server
                sendMessage(clientSocket, sendBuffer);
                readMessage(clientSocket, recvBuffer);
                if (strncmp(recvBuffer, "Peer", 4) == 0) { // Peer offline
                    printf("%s", recvBuffer);
                    continue;
                }
                
                struct sockaddr_in peerAddress;
                socklen_t addrlen = sizeof(peerAddress); // length of address
                peerAddress.sin_family = AF_INET; // address family is IPv4
                read(clientSocket, &(peerAddress.sin_addr.s_addr), sizeof(in_addr_t));
                read(clientSocket, &(peerAddress.sin_port), sizeof(in_port_t));

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
                
                DMOngoing = true;
                strcpy(currentPeerID, inputTokens[1]);
                oneToOneChat();
                close(peerSocket);
                DMOngoing = false;
                
            } else {
                printf("Invalid parameters.\nUsage: chat <ID>\n");
            }
            
//MARK: - Accept DM
        } else if (strcmp(token, "accept") == 0){
            if (!loggedIn) {
                printf("You are currently not logged in, plaese login to use this feature.\n");
                continue;
            }
            if (!pendingRequest) {
                printf(YELLOW("No incoming message request now\n"));
                continue;
            }
            if (DMOngoing) {
                printf(RED("Cannot have more than one ongoing chat at once\n"));
                continue;
            }
            
            // Notify acceptDM thread NOT ready to accpet next incoming request
            pthread_mutex_lock(&mutex);
            DMOngoing = true;
            acceptSignal = true;
            pthread_cond_signal(&readyToAccept);
            pthread_mutex_unlock(&mutex);
            
            char inputBuffer[BUFFERSIZE] = {0}; // buffer for user input
            
            // Create message reciever thread for chat
            if (pthread_create(&messageReciever, NULL, recvMessage, currentPeerID) != 0) {
                perror(RED("[ERROR]")" Failed to create message reciever thread\n");
                exit(EXIT_FAILURE);
            }
            char response[] = "yes";
            sendMessage(peerSocket, response);
            
            printf("Type \"leave chat\" to leave the current chat\n");
            // Keep reading user input and send them
            while (true) {
                printf(BRED(BOLD("%s>"))" ", currentUserID);
                fgets(inputBuffer, BUFFERSIZE, stdin); // read whole line of input
                inputBuffer[strcspn(inputBuffer, "\n")] = '\0'; // trim off the newline character at the end
                if (strcmp(inputBuffer, "leave chat") == 0) {
                    break;
                }
                if (sendMessage(peerSocket, inputBuffer) < 0) {
                    break;
                }
            }
            char closeConnection[] = "CLOSEDM";
            sendMessage(peerSocket, closeConnection);
            
            // Cancel the message recieving thread
            pthread_cancel(messageReciever);
            pthread_join(messageReciever, NULL);
            close(peerSocket);
            peerSocket = -1;
            currentPeerID[0] = '\0';
            
            pthread_mutex_lock(&mutex);
            DMOngoing = false;
            acceptSignal = false;
            pthread_cond_signal(&readyToAccept); // notify acceptDM thread ready to accpet next incoming request
            pthread_mutex_unlock(&mutex);
            
//MARK: - Help
        } else if (strcmp(token, "help") == 0) {
            printf(YELLOW("%-36s")": %-25s\n", "Registration", "register <ID> <password>");
            printf(YELLOW("%-36s")": %-25s\n", "Deregistration(must be logged in)", "deregister <ID> <password>");
            printf(YELLOW("%-36s")": %-25s\n", "Login(must be registered)", "login <ID> <password>");
            printf(YELLOW("%-36s")": %-25s\n", "Logout(must be logged in)", "logout");
            printf(YELLOW("%-36s")": %-25s\n", "List Online Users(must be logged in)", "list");
            printf(YELLOW("%-36s")": %-25s\n", "Chat with user(must be logged in)", "chat <ID>");
            printf(YELLOW("%-36s")": %-25s\n", "Exit Client Program", "exit");
        } else {
            printf("Unknown command, type \"help\" for usage.\n");
        }
    }
    
    pthread_cancel(DMAcceptor);
    pthread_join(DMAcceptor, NULL);
    
    return 0;
}

static void *acceptDM(void *arg) {
    int listeningSocket = *(int *)arg;
    struct sockaddr_in address; // IP and port number to bind the socket to
    socklen_t addrlen = sizeof(address); // length of address
    
    while (true) {
        if ((peerSocket = accept(listeningSocket, (struct sockaddr*)&address, &addrlen)) < 0) {
            fprintf(stderr, RED("[ERROR]")" Accepting connection failed\n");
            continue;
        }
        readMessage(peerSocket, currentPeerID);
        printf("\n[INCOMING] %s wants to chat, accept? [accept](30s)\n", currentPeerID);
        printf(BOLD("%s> "), currentUserID);
        fflush(stdout);
        
        // Wait 30 seconds or request accepted
        pthread_mutex_lock(&mutex);
        pendingRequest = true;
        // Compute wake-up time (30 seconds from now)
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 30;

        // Wait for accept or timeout
        while (!acceptSignal) {
            int ret = pthread_cond_timedwait(&readyToAccept, &mutex, &ts);
            if (ret == ETIMEDOUT) {
                sendMessage(peerSocket, "no");
                currentPeerID[0] = '\0';
                close(peerSocket);
                peerSocket = -1;
                pendingRequest = false;
                break;
            }
        }
      
        while (DMOngoing) {
            pthread_cond_wait(&readyToAccept, &mutex);
        }
        pendingRequest = false;
        pthread_mutex_unlock(&mutex);
    }
    
    return NULL;
}

static void oneToOneChat(void) {
    char response[3];
    sendMessage(peerSocket, currentUserID); // Send messaging request
    printf("Waiting for peer to repond, please wait(30s)...\n");
    readMessage(peerSocket, response);
    
    if (strcmp(response, "no") == 0) {
        printf(YELLOW("Peer did not accept DM request :(\n"));
    } else {
        char inputBuffer[BUFFERSIZE] = {0}; // buffer for user input
        
        // Create message reciever thread for chat
        if (pthread_create(&messageReciever, NULL, recvMessage, NULL) != 0) {
            perror(RED("[ERROR]")" Failed to create message reciever thread\n");
            exit(EXIT_FAILURE);
        }
        printf("Type \"leave chat\" to leave the current chat\n");
        
        // Keep reading user input and send them
        while (true) {
            printf(BRED(BOLD("%s>"))" ", currentUserID);
            fgets(inputBuffer, BUFFERSIZE, stdin); // read whole line of input
            inputBuffer[strcspn(inputBuffer, "\n")] = '\0'; // trim off the newline character at the end
            if (strcmp(inputBuffer, "leave chat") == 0) {
                break;
            }
            if (sendMessage(peerSocket, inputBuffer) < 0) {
                break;
            }
        }
        char closeConnection[] = "CLOSEDM";
        sendMessage(peerSocket, closeConnection);
        
        // Cancel the message recieving thread
        pthread_cancel(messageReciever);
        pthread_join(messageReciever, NULL);
    }
    
    return;
}

static void *recvMessage(void *arg) {
    char recvBuffer[BUFFERSIZE] = {0}; // buffer for messages from server
    while (true) {
        readMessage(peerSocket, recvBuffer);
        if (strcmp(recvBuffer, "CLOSEDM") == 0) {
            currentPeerID[0] = '\0';
            close(peerSocket);
            peerSocket = -1;
            printf("\n"YELLOW("Peer had left.")"\n"BOLD("%s> "), currentUserID);
            break;
        } else {
            printf("\n"BBLUE("%s:")" ", currentPeerID);
            printf(BLUE("%s")"\n", recvBuffer);
            printf(BRED(BOLD("%s>"))" ", currentUserID);
            fflush(stdout);
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
    int maxWaitingToConnect = 10;
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

static void readMessage(int socket, char *buffer) {
    int32_t messageLength;
    read(socket, &messageLength, sizeof(messageLength));
    read(socket, buffer, ntohl(messageLength));
    return;
}

static int parseInput(char *token, char *buffer, char (*input)[BUFFERSIZE]){
    int parameterIndex = 0;
    while (token != NULL) {
        if (parameterIndex >= 4) {
            break;
        }
        strcpy(input[parameterIndex], token);
        strcat(buffer, token);
        strcat(buffer, " ");
        token = strtok(NULL, " ");
        parameterIndex++;
    } // rebuild user input
    return parameterIndex;
}

static int setListeingPort(int argc, const char **argv) {
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
