#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdbool.h>

#define SERVERPORT 12000
#define BUFFERSIZE 1024

int main(int argc, char const* argv[]) {
//MARK: - Socket Setup
    int clientSocket;
    struct sockaddr_in serverAddress; // IP and port number to bind the socket to
    socklen_t addrlen = sizeof(serverAddress); // length of address
    
    // Create socket file descriptor
    if ((clientSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("\nSocket creation failed\n");
        exit(EXIT_FAILURE);
    }
    
    address.sin_family = AF_INET; // address family is IPv4
    address.sin_port = htons(SERVERPORT); // set port number
    
    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &serverAddress.sin_addr) <= 0) {
        perror("\nInvalid address/ Address not supported \n");
        exit(EXIT_FAILURE);
    }
    
    // Continue reading and sending messages
    char buffer[BUFFERSIZE] = {0};
    char inputBuffer[BUFFERSIZE] = {0};
    int readVal;
    bool loggedIn = false;
    
    while (true) {
        // Take user input
        scanf("%s", inputBuffer);
        char *token; // Pointer to store each token
        token = strtok(inputBuffer, " "); // Get the first token
       
//MARK: - Exit
        if (strcmp(token, "exit") == 0) { // exit and end the client process
            if (loggedIn) {
                strcpy(token, "logout");
                send(clientSocket, token, strlen(token), 0); // Tell the server to logout the user
                readVal = read(clientSocket, buffer, BUFFERSIZE - 1); // Server response
                
                // closing the connected socket
                close(clientSocket);
                
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
                readVal = read(clientSocket, buffer, BUFFERSIZE - 1); // Server response
                
                // closing the connected socket
                close(clientSocket);
                
                loggedIn = false;
                printf("%s", buffer);
            }
//MARK: - Register
        } else if (strcmp(token, "register") == 0) {
            char inputTokens[3][BUFFERSIZE] = {0};
            strcpy(inputTokens[0], token);
            int parameterIndex = 1;
            while (token != NULL) { // Loop through the remaining tokens
                if (parameterIndex >= 3) {
                    break;
                }
                strcpy(inputTokens[i], token);
                token = strtok(NULL, " "); // Get the next token
                parameterIndex++;
            }
            
            if (parameterIndex == 2) {
                if (loggedIn) {
                    printf("You are already logged in to an account, please logout before creating a new account.\n");
                } else {
                    
                    // Connect to server
                    int status;
                    if ((status = connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress))) < 0) {
                        perror("\nConnection to server failed \n");
                        exit(EXIT_FAILURE);
                    }
                    

                    send(clientSocket, inputTokens[0], strlen(inputTokens[0]), 0); // Send the server registration command
                    send(clientSocket, inputTokens[2], strlen(inputTokens[2]), 0); // Send the server password
                    send(clientSocket, inputTokens[1], strlen(inputTokens[1]), 0); // Send the server ID
                    
                    readVal = read(clientSocket, buffer, BUFFERSIZE - 1); // Server response
                    while (strncmp(buffer, "This ID has been taken", 22) == 0) {
                        printf("%s", buffer);
                        scanf("%s", inputBuffer);
                        send(clientSocket, inputBuffer, strlen(inputBuffer), 0);
                        readVal = read(clientSocket, buffer, BUFFERSIZE - 1);
                    }

                    // closing the connected socket
                    close(clientSocket);
                    
                    printf("%s", buffer);
                }
            } else {
                printf("Invalid parameters.\nUsage: register [ID] [password]\n");
            }
//MARK: - Login
        } else if (strcmp(token, "login") == 0) {
            char inputTokens[3][BUFFERSIZE] = {0};
            strcpy(inputTokens[0], token);
            int parameterIndex = 1;
            while (token != NULL) { // Loop through the remaining tokens
                if (parameterIndex >= 3) {
                    break;
                }
                strcpy(inputTokens[i], token);
                token = strtok(NULL, " "); // Get the next token
                parameterIndex++;
            }
            
            if (parameterIndex == 2) {
                if (loggedIn) {
                    printf("You are already logged in to an account, please logout before logging in to another account.\n");
                } else {
                    
                    // Connect to server
                    int status;
                    if ((status = connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress))) < 0) {
                        perror("\nConnection to server failed \n");
                        exit(EXIT_FAILURE);
                    }
                    
                    for (int t = 0; t < 3; t++) {
                        send(clientSocket, inputTokens[t], strlen(inputTokens[t]), 0); // Send the server login parameters
                    }
                    
                    readVal = read(clientSocket, buffer, BUFFERSIZE - 1); // Server response
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
                readVal = read(clientSocket, buffer, BUFFERSIZE - 1); // Server response
                printf("Online Users\n====================\n");
                while (strcmp(buffer, "END OF USER LIST") != 0) {
                    printf("%s\n", buffer);
                    readVal = read(clientSocket, buffer, BUFFERSIZE - 1);
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
