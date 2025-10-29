#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>

#include "client.h"

#define SERVERPORT 12014
#define BUFFERSIZE 1024

int main(int argc, char const* argv[]) {
//MARK: - Socket Setup
    if (argc != 2) {
        printf(RED("Usage: ./client.out <Listening port number>\n"));
        exit(-1);
    }
    
    int listeningSocket = 0, clientSocket = 0;
    int listeningPort = atoi(argv[1]); // socket fd
    if (listeningPort < 49152 || listeningPort > 65535) {
        printf(RED("Invalid port number, please choose in the range of [49152, 65535]\n"));
        exit(-1);
    }
    
    listeningSocket = setListeningSocket(listeningSocket, listeningPort);
    
    char buffer[BUFFERSIZE] = {0}; // buffer for messages from server
    char inputBuffer[BUFFERSIZE] = {0}; // buffer for user input
    ssize_t readVal; // read return value
    bool loggedIn = false; // is the user currently logged in
    
    //int32_t messageLength;
    while (true) {
        printf("> ");
        fgets(inputBuffer, BUFFERSIZE, stdin); // read whole line of input
        inputBuffer[strcspn(inputBuffer, "\n")] = '\0'; // trim off the newline character at the end
        char *token; // Pointer to store each token
        token = strtok(inputBuffer, " "); // Get the first token of input
       
//MARK: - Exit
        if (strcmp(token, "exit") == 0) { // exit and end the client process
            if (loggedIn) {
                strcpy(token, "logout");
                sendMessage(clientSocket, token);
                readMessage(clientSocket, buffer);
                close(clientSocket); // close connection
                
                loggedIn = false;
                printf("%s", buffer);
            }
            break;
//MARK: - Logout
        } else if (strcmp(token, "logout") == 0) { // logout put keeps the client process running
            if (!loggedIn) {
                printf("You are currently not logged in to any account.\n");
            } else {
                sendMessage(clientSocket, token);
                readMessage(clientSocket, buffer);
                close(clientSocket); // close connection
                
                loggedIn = false;
                printf("%s", buffer);
            }
//MARK: - Register
        } else if (strcmp(token, "register") == 0) {
            int parameterIndex = 0;
            char sendBuffer[BUFFERSIZE] = "";
            while (token != NULL) {
                if (parameterIndex >= 4) {
                    break;
                }
                strcat(sendBuffer, token);
                strcat(sendBuffer, " ");
                token = strtok(NULL, " ");
                parameterIndex++;
            } // rebuild user input
            
            if (parameterIndex == 3) { // correct number of parameters
                if (loggedIn) {
                    printf("You are already logged in to an account, please logout before creating a new account.\n");
                } else {
                    clientSocket = connectToServer(clientSocket); // connect
                    sendMessage(clientSocket, sendBuffer);
                    readMessage(clientSocket, buffer);
                    close(clientSocket); // close connection
                    printf("%s", buffer);
                }
            } else {
                printf("Invalid parameters.\nUsage: register <ID> <password>\n");
            }
//MARK: - Login
        } else if (strcmp(token, "login") == 0) {
            int parameterIndex = 0;
            char sendBuffer[BUFFERSIZE] = "";
            while (token != NULL) {
                if (parameterIndex >= 4) {
                    break;
                }
                strcat(sendBuffer, token);
                strcat(sendBuffer, " ");
                token = strtok(NULL, " ");
                parameterIndex++;
            } // rebuild user input
            
            if (parameterIndex == 3) { // correct number of parameters
                if (loggedIn) {
                    printf("You are already logged in to an account, please logout before logging in to another account.\n");
                } else {
                    clientSocket = connectToServer(clientSocket); // connect
                    sendMessage(clientSocket, sendBuffer);
                    readMessage(clientSocket, buffer);
                    
                    if (strncmp(buffer, "OK.", 3) == 0) { // if successfully logged in
                        int32_t formatted = htons(listeningPort);
                        send(clientSocket, &formatted, sizeof(int32_t), 0);
                        loggedIn = true;
 
                        readMessage(clientSocket, buffer);
                    }
                    
                    printf("%s", buffer);
                }
            } else {
                printf("Invalid parameters.\nUsage: login <ID> <password>\n");
            }
//MARK: - List
        } else if (strcmp(token, "list") == 0) {
            if (!loggedIn) {
                printf("You are currently not logged in, plaese login to use this feature.\n");
            } else {
                sendMessage(clientSocket, token);
                readMessage(clientSocket, buffer);
                
                printf(GREEN("Online Users\n====================\n"));
                while (strcmp(buffer, "END OF USER LIST") != 0) {
                    printf(GREEN("%s\n"), buffer);
                    readMessage(clientSocket, buffer);
                }
            }
//MARK: - Help
        } else if (strcmp(token, "help") == 0) {
            printf(YELLOW("%-36s")": %-25s\n", "Registration", "register <ID> <password>");
            printf(YELLOW("%-36s")": %-25s\n", "Login(must be registered)", "login <ID> <password>");
            printf(YELLOW("%-36s")": %-25s\n", "Logout(must be logged in)", "logout");
            printf(YELLOW("%-36s")": %-25s\n", "List Online Users(must be logged in)", "list");
            printf(YELLOW("%-36s")": %-25s\n", "Exit Client Program", "exit");
        } else {
            printf("Unknown command, type \"help\" for usage.\n");
        }
    }
    
    return 0;
}

int connectToServer(int clientSocket) {
    
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
    int status;
    if ((status = connect(clientSocket, (struct sockaddr*)&serverAddress, addrlen)) < 0) {
        perror(RED("Connection to server failed\n"));
        exit(EXIT_FAILURE);
    }
    
    return clientSocket;
}

int setListeningSocket(int listeningSocket, int listeningPort) {
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
    
    return listeningSocket;
}

void sendMessage(int socket, char *buffer) {
    int32_t messageLength = htonl(strlen(buffer) + 1);
    send(socket, &messageLength, sizeof(messageLength), 0);
    send(socket, buffer, strlen(buffer) + 1, 0);
    return;
}

void readMessage(int socket, char *buffer) {
    int32_t messageLength;
    read(socket, &messageLength, sizeof(messageLength));
    read(socket, buffer, ntohl(messageLength));
    return;
}
