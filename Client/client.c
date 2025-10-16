#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>

#define SERVERPORT 12000
#define BUFFERSIZE 1024

int connectToServer(int clientSocket) {
    
    struct sockaddr_in serverAddress; // IP and port number to bind the socket to
    socklen_t addrlen = sizeof(serverAddress); // length of address
    
    // Create socket file descriptor
    if ((clientSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("\nSocket creation failed\n");
        exit(EXIT_FAILURE);
    }
    
    serverAddress.sin_family = AF_INET; // address family is IPv4
    serverAddress.sin_port = htons(SERVERPORT); // set port number
    
    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &serverAddress.sin_addr) <= 0) {
        perror("\nInvalid address/ Address not supported \n");
        exit(EXIT_FAILURE);
    }
    
    // Connect to server
    int status;
    if ((status = connect(clientSocket, (struct sockaddr*)&serverAddress, addrlen)) < 0) {
        perror("\nConnection to server failed \n");
        exit(EXIT_FAILURE);
    }
    
    return clientSocket;
}

int main(int argc, char const* argv[]) {
//MARK: - Socket Setup
    int clientSocket = 0; // socket fd
    char buffer[BUFFERSIZE] = {0}; // buffer for messages from server
    char inputBuffer[BUFFERSIZE] = {0}; // buffer for user input
    ssize_t readVal; // read return value
    bool loggedIn = false; // is the user currently logged in
    
    while (true) {
        memset(buffer, 0, sizeof(buffer)); // clear buffer
        printf("> ");
        fgets(inputBuffer, BUFFERSIZE, stdin); // read whole line of input
        inputBuffer[strcspn(inputBuffer, "\n")] = '\0'; // trim off the newline character at the end
        char *token; // Pointer to store each token
        token = strtok(inputBuffer, " "); // Get the first token of input
       
//MARK: - Exit
        if (strcmp(token, "exit") == 0) { // exit and end the client process
            if (loggedIn) {
                strcpy(token, "logout");
                send(clientSocket, token, strlen(token), 0); // Tell the server to logout the user
                readVal = read(clientSocket, buffer, BUFFERSIZE); // Server response
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
                send(clientSocket, token, strlen(token), 0); // Tell the server to logout the user
                readVal = read(clientSocket, buffer, BUFFERSIZE ); // Server response
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
                    send(clientSocket, sendBuffer, sizeof(sendBuffer), 0); // send request
                    readVal = read(clientSocket, buffer, BUFFERSIZE); // Server response
                    close(clientSocket); // close connection
                    printf("%s", buffer);
                }
            } else {
                printf("Invalid parameters.\nUsage: register [ID] [password]\n");
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
                    send(clientSocket, sendBuffer, sizeof(sendBuffer), 0); // send request
                    readVal = read(clientSocket, buffer, BUFFERSIZE); // Server response
                    
                    if (strncmp(buffer, "Successfully logged in.", 23) == 0) { // if successfully logged in
                        loggedIn = true;
                    }
                    
                    printf("%s", buffer);
                }
            } else {
                printf("Invalid parameters.\nUsage: login [ID] [password]\n");
            }
//MARK: - List
        } else if (strcmp(token, "list") == 0) {
            if (!loggedIn) {
                printf("You are currently not logged in, plaese login to use this feature.\n");
            } else {
                send(clientSocket, token, strlen(token), 0); // Tell the server to list users
                readVal = read(clientSocket, buffer, BUFFERSIZE); // Server response
                printf("Online Users\n====================\n");
                while (strcmp(buffer, "END OF USER LIST") != 0) {
                    printf("%s\n", buffer);
                    memset(buffer, 0, sizeof(buffer)); // clear buffer
                    readVal = read(clientSocket, buffer, BUFFERSIZE);
                }
            }
//MARK: - Help
        } else if (strcmp(token, "help") == 0) {
            printf("Registration: register [ID] [password]\nLogin(must be registered): login [ID] [password]\nLogout(must be logged in): logout\nList Online Users(must be logged in): list\nExit Client Program: exit\n");
        } else {
            printf("Unknown command, type \"help\" for usage.\n");
        }
    }
    
    return 0;
}
