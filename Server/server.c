#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdbool.h>
#include <poll.h>

#define SERVERPORT 12000
#define BUFFERSIZE 1024

typedef struct userClient {
    char ID[BUFFERSIZE];
    char password[BUFFERSIZE];
    struct sockaddr_in address;
    struct userClient *next;
    struct userClient *prev;
} User;

int main(int argc, char const* argv[]) {
//MARK: - Socket Setup
    int serverSocket, perClientSocket; // socket used for listening and socket created for each client
    struct sockaddr_in address; // IP and port number to bind the socket to
    socklen_t addrlen = sizeof(address); // length of address
    
    // Create socket file descriptor, use IPv4 and TCP
    if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("\nSocket creation failed\n");
        exit(EXIT_FAILURE);
    }
    
    // Attach serverSocket to the port 12000
    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("\nSet socket options failed\n");
        exit(EXIT_FAILURE);
    }
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("\nSet socket options failed\n");
        exit(EXIT_FAILURE);
    }
    
    address.sin_family = AF_INET; // address family is IPv4
    address.sin_addr.s_addr = INADDR_ANY; // socket will be bound to all local interfaces
    address.sin_port = htons(SERVERPORT); // set port number
    if (bind(serverSocket, (struct sockaddr*)&address, addrlen) < 0) {
        perror("\nBinding socket to port failed\n");
        exit(EXIT_FAILURE);
    }
    
    // Listen for connections
    int maxWaitingToConnect = 10;
    User *registeredUsers = NULL;
    User *loggedInUsers = NULL;
    
    while (true) { // keep listening for new connections
        if (listen(serverSocket, maxWaitingToConnect) < 0) {
            perror("\nListening for connection failed\n");
            exit(EXIT_FAILURE);
        }
        
        // Accept connections
        if ((perClientSocket = accept(serverSocket, (struct sockaddr*)&address, &addrlen)) < 0) {
            perror("\nAccepting connection failed\n");
            exit(EXIT_FAILURE);
        }
        fprintf(stderr, "Accepted client connection\n");
        
        struct pollfd pollfd;
        pollfd.fd = perClientSocket;     // your client socket fd
        pollfd.events = POLLIN;          // interested in read readiness

        // Read from socket and store in buffer
        char buffer[BUFFERSIZE] = {0};
        char currentUserID[BUFFERSIZE] = {0};
        ssize_t readVal;
        
        while (true) { // keep reading and processing messages from the current client
            int pollResult = poll(&pollfd, 1, -1);  // 1 fd, wait forever
            if (pollResult <= 0) {
                continue;
            }
            
            readVal = read(perClientSocket, buffer, BUFFERSIZE - 1);
            if (readVal <= 1) {
                continue;
            }
            fprintf(stderr, "Buffer: %s\n", buffer);
            
            char *token; // Pointer to store each token
            token = strtok(buffer, " "); // Get the first token
            
            //MARK: - Logout
            if (strcmp(token, "logout") == 0) { // client wants to disconnect
                // update currently looged in users
                User *u = loggedInUsers;
                while (u != NULL) {
                    if (strcmp(u -> ID, currentUserID) == 0) {
                        u -> prev -> next = u -> next;
                        if (u -> next != NULL) {
                            u -> next -> prev = u -> prev;
                        }
                        free(u);
                        break;
                    }
                }
                char sendBuffer[] = "Successfully logged out.\n";
                send(perClientSocket, sendBuffer, strlen(sendBuffer), 0);
                
                // Close the connected socket
                close(perClientSocket);
                break;
                //MARK: - Register
            } else if (strcmp(token, "register") == 0) { // registration
                char inputTokens[3][BUFFERSIZE] = {0}; // 1 = ID, 2 = password
                int parameterIndex = 0;
                while (token != NULL) { // Loop through the remaining tokens
                    strcpy(inputTokens[parameterIndex], token);
                    token = strtok(NULL, " "); // Get the next token
                    parameterIndex++;
                }
                
                while (true) { // retry until ID is unique or registration cancelled
                    
                    if (strcmp(inputTokens[1], "CANCEL") == 0) { // user cancels registration
                        strcpy(inputTokens[2], "");
                        char completionMessage[] = "Registration cancelled.\n";
                        send(perClientSocket, completionMessage, strlen(completionMessage), 0);
                        break;
                    }
                    
                    // check if user ID is already taken
                    bool userExists = false;
                    User *u = registeredUsers;
                    while (u != NULL) {
                        if (strcmp(u -> ID, inputTokens[1]) == 0) {
                            userExists = true;
                            break;
                        }
                    }
                    if (!userExists) { // if not, insert new user to linked list
                        User *newUser = (User *)calloc(1, sizeof(User));
                        strcpy(newUser -> ID, inputTokens[1]);
                        strcpy(newUser -> password, inputTokens[2]);
                        if (registeredUsers == NULL) {
                            registeredUsers = newUser;
                        } else {
                            registeredUsers -> prev = newUser;
                            newUser -> next = registeredUsers;
                            registeredUsers = newUser;
                        }
                        
                        char completionMessage[] = "Registration complete, please login to start using the service.\n";
                        send(perClientSocket, completionMessage, strlen(completionMessage), 0);
                        break;
                        
                    } else {
                        char errorMessage[] = "This ID has been taken, please choose another one or type \"CANCEL\" to cancel the registration process.\n";
                        send(perClientSocket, errorMessage, strlen(errorMessage), 0);
                    }
                    
                    readVal = read(perClientSocket, buffer, BUFFERSIZE - 1);
                    token = strtok(buffer, " ");
                    parameterIndex = 0;
                    while (token != NULL) { // Loop through the remaining tokens
                        strcpy(inputTokens[parameterIndex], token);
                        token = strtok(NULL, " "); // Get the next token
                        parameterIndex++;
                    }
                }
                //MARK: - Login
            } else if (strcmp(token, "login") == 0) {
                char ID[BUFFERSIZE] = {0};
                char password[BUFFERSIZE] = {0};
                readVal = read(perClientSocket, ID, BUFFERSIZE - 1);
                readVal = read(perClientSocket, password, BUFFERSIZE - 1);
                
                // check if user is already registered
                bool userRegistered = false;
                User *u = registeredUsers;
                while (u != NULL) {
                    if (strcmp(u -> ID, ID) == 0) {
                        userRegistered = true;
                        break;
                    }
                }
                
                // user not registered
                if (!userRegistered) {
                    char errorMessage[] = "No know user with this ID, please register first.\n";
                    send(perClientSocket, errorMessage, strlen(errorMessage), 0);
                    continue;
                }
                // user registered, check password
                if (strcmp(u -> password, password) != 0) {
                    char errorMessage[] = "Incorrect password, please try again.\n";
                    send(perClientSocket, errorMessage, strlen(errorMessage), 0);
                    continue;
                }
                // password correct, insert to logged in list
                User *newLogin = (User *)calloc(1, sizeof(User));
                strcpy(newLogin -> ID, ID);
                newLogin -> address = address;
                
                if (loggedInUsers == NULL) { // insert to list
                    loggedInUsers = newLogin;
                } else {
                    newLogin -> next = loggedInUsers;
                    loggedInUsers -> prev = newLogin;
                    loggedInUsers = newLogin;
                }
                
                char completionMessage[] = "Successfully logged in.\n\nAvailable Services\n====================\nLogout: logout\nList Online Users: list\n";
                send(perClientSocket, completionMessage, strlen(completionMessage), 0);
                //MARK: - List
            } else if (strcmp(token, "list") == 0) {
                User *u = loggedInUsers;
                while (u != NULL) {
                    send(perClientSocket, u -> ID, strlen(u -> ID), 0);
                }
                char completionMessage[] = "END OF USER LIST";
                send(perClientSocket, completionMessage, strlen(completionMessage), 0);
            }
            
            strcpy(buffer, "");
        }
    }
    
    // Close the listening socket
    //close(serverSocket);
    
    return 0;
}
