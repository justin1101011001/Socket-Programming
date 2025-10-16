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
        fprintf(stderr, "Listening for connections\n");
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
        ssize_t readVal;
        User *currentUser = NULL;
        
        while (true) { // keep reading and processing messages from the current client
//            int pollResult = poll(&pollfd, 1, -1);  // 1 fd, wait forever
//            if (pollResult <= 0) {
//                continue;
//            }
            
            memset(buffer, 0, sizeof(buffer)); // clear buffer
            readVal = read(perClientSocket, buffer, BUFFERSIZE);
//            if (readVal <= 0) {
//                continue;
//            }
            fprintf(stderr, "Client: %s\n", buffer);
            
            char *token; // Pointer to store each token
            token = strtok(buffer, " "); // Get the first token
//MARK: - Logout
            if (strcmp(token, "logout") == 0) { // client wants to disconnect
                fprintf(stderr, "Start logout process\n");
                // update currently looged in users
                if (loggedInUsers == currentUser) {
                    loggedInUsers = currentUser -> next;
                }
                if (currentUser -> prev != NULL) {
                    currentUser -> prev -> next = currentUser -> next;
                }
                if (currentUser -> next != NULL) {
                    currentUser -> next -> prev = currentUser -> prev;
                }
                free(currentUser);
                
                char sendBuffer[] = "Successfully logged out.\n";
                send(perClientSocket, sendBuffer, strlen(sendBuffer), 0);
                
                // Close connection
                close(perClientSocket);
                break;
//MARK: - Register
            } else if (strcmp(token, "register") == 0) { // registration
                fprintf(stderr, "Start register process\n");
                char inputTokens[3][BUFFERSIZE] = {0}; // 1 = ID, 2 = password
                int parameterIndex = 0;
                while (token != NULL) {
                    strcpy(inputTokens[parameterIndex], token);
                    token = strtok(NULL, " ");
                    parameterIndex++;
                } // tokenize input
                
                fprintf(stderr, "Check if user exists\n");
                // check if user ID is already taken
                bool userExists = false;
                User *u = registeredUsers;
                while (u != NULL) {
                    if (strcmp(u -> ID, inputTokens[1]) == 0) {
                        userExists = true;
                        break;
                    }
                    u = u -> next;
                }
                
                if (!userExists) { // if not, insert new user to linked list
                    fprintf(stderr, "Insert new user\n");
                    User *newUser = (User *)calloc(1, sizeof(User));
                    newUser -> next = NULL;
                    newUser -> prev = NULL;
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
                    
                } else {
                    fprintf(stderr, "User already exists\n");
                    char errorMessage[] = "This ID has been taken, please choose another one.\n";
                    send(perClientSocket, errorMessage, strlen(errorMessage), 0);
                }
                
                // Close connection
                close(perClientSocket);
                fprintf(stderr, "Connection closed\n");
                break;
                
//MARK: - Login
            } else if (strcmp(token, "login") == 0) {
                fprintf(stderr, "Start login process\n");
                char inputTokens[3][BUFFERSIZE] = {0}; // 1 = ID, 2 = password
                int parameterIndex = 0;
                while (token != NULL) {
                    strcpy(inputTokens[parameterIndex], token);
                    token = strtok(NULL, " ");
                    parameterIndex++;
                } // tokenize input
                
                fprintf(stderr, "Check if user is registered\n");
                // check if user is already registered
                bool userRegistered = false;
                User *u = registeredUsers;
                while (u != NULL) {
                    if (strcmp(u -> ID, inputTokens[1]) == 0) {
                        userRegistered = true;
                        break;
                    }
                    u = u -> next;
                }
                
                // user not registered
                if (!userRegistered) {
                    fprintf(stderr, "User not registered\n");
                    char errorMessage[] = "No know user with this ID, please register first.\n";
                    send(perClientSocket, errorMessage, strlen(errorMessage), 0);
                    
                    // Close the connected socket
                    close(perClientSocket);
                    fprintf(stderr, "Connection closed\n");
                    break;
                }
                
                fprintf(stderr, "Check password\n");
                // user registered, check password
                if (strcmp(u -> password, inputTokens[2]) != 0) {
                    char errorMessage[] = "Incorrect password, please try again.\n";
                    send(perClientSocket, errorMessage, strlen(errorMessage), 0);
                    
                    // Close connection
                    close(perClientSocket);
                    fprintf(stderr, "Connection closed\n");
                    break;
                }
                
                fprintf(stderr, "Insert new login\n");
                // password correct, insert to logged in list
                User *newLogin = (User *)calloc(1, sizeof(User));
                newLogin -> next = NULL;
                newLogin -> prev = NULL;
                newLogin -> address = address;
                strcpy(newLogin -> ID, inputTokens[1]);
                
                if (loggedInUsers == NULL) { // insert to list
                    loggedInUsers = newLogin;
                } else {
                    newLogin -> next = loggedInUsers;
                    loggedInUsers -> prev = newLogin;
                    loggedInUsers = newLogin;
                }
                
                currentUser = newLogin;
                
                char completionMessage[] = "Successfully logged in.\nAvailable Services\n====================\nLogout: logout\nList Online Users: list\n";
                send(perClientSocket, completionMessage, strlen(completionMessage), 0);
                //MARK: - List
            } else if (strcmp(token, "list") == 0) {
                User *u = loggedInUsers;
                while (u != NULL) {
                    send(perClientSocket, u -> ID, BUFFERSIZE, 0);
                    u = u -> next;
                }
                char completionMessage[] = "END OF USER LIST";
                send(perClientSocket, completionMessage, BUFFERSIZE, 0);
            }
        }
    }
    
    // Close the listening socket
    //close(serverSocket);
    
    return 0;
}
