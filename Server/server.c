#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "server.h"

#define SERVERPORT 12014
#define BUFFERSIZE 1024
#define THREAD_POOL_SIZE 10
#define JOB_QUEUE_SIZE 16

// Mutexes for user lists
pthread_mutex_t registeredUsers_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t loggedInUsers_mutex = PTHREAD_MUTEX_INITIALIZER;

// Global user lists
User *registeredUsers = NULL;
User *loggedInUsers = NULL;

// Global job queue
JobQueue job_queue;

int main(int argc, char const* argv[]) {
//MARK: - main
    int serverSocket = 0, perClientSocket = 0; // socket used for listening and socket created for each client

    queue_init(&job_queue); // Initialize job queue
    serverSocket = setSocket(serverSocket); // Set up server listening socket
    createThreads(); // Create worker threads for handling clients

    while (true) { // keep listening for new connections
        fprintf(stderr, MAGENTA("[LOG]")" Listening for connections\n");
        perClientSocket = acceptConnection(perClientSocket, serverSocket); // Accept connections
        queue_push(&job_queue, perClientSocket); // Add accepted client socket to the job queue for worker threads
    }

    return 0;
}

// MARK: - Chat Functions
// Handle client communication and commands
static void handle_client(int perClientSocket) {
    
    char recvBuffer[BUFFERSIZE] = {0};
    User *currentUser = NULL;

    // Get client address info
    struct sockaddr_in client_address;
    socklen_t client_addrlen = sizeof(client_address);
    getpeername(perClientSocket, (struct sockaddr*)&client_address, &client_addrlen);
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_address.sin_addr), ip_str, INET_ADDRSTRLEN); // IP
    int port = ntohs(client_address.sin_port); // Port

    while (true) { // keep reading and processing messages from the current client
        
        readMessage(perClientSocket, recvBuffer);
        fprintf(stderr, CYAN("[MESSAGE]")" Client %s:%d: %s\n", ip_str, port, recvBuffer);
        char *token; // Pointer to store each token
        token = strtok(recvBuffer, " ");
        if (token == NULL) {
            // Empty command, continue reading
            continue;
        }

//MARK: - Logout
        if (strcmp(token, "logout") == 0) { // client wants to disconnect
            fprintf(stderr, MAGENTA("[LOG]")" Start logout process\n");
            if (currentUser != NULL) {
                removeFromLoggedIn(&currentUser);
                fprintf(stderr, MAGENTA("[LOG]")"  | Removed user from logged-in list\n");
            }

            char sendBuffer[] = "Successfully logged out.\n";
            sendMessage(perClientSocket, sendBuffer);

            close(perClientSocket);
            fprintf(stderr, MAGENTA("[LOG]")"  | Connection to client %s:%d closed\n", ip_str, port);
            fprintf(stderr, MAGENTA("[LOG]")"  +-Logout process complete\n");
            break;
//MARK: - Register
        } else if (strcmp(token, "register") == 0) { // registration
            fprintf(stderr, MAGENTA("[LOG]")" Start register process\n");
            char inputTokens[3][BUFFERSIZE] = {0}; // 1 = ID, 2 = password
            parseMessage(token, inputTokens);

            // check if user ID is already taken
            fprintf(stderr, MAGENTA("[LOG]")"  | Checking if user exists\n");
            User *userExists = checkUserInList(&registeredUsers, inputTokens[1], &registeredUsers_mutex);

            if (!userExists) { // if not, insert new user to linked list
                fprintf(stderr, MAGENTA("[LOG]")"  | User doesn't exit\n");
                fprintf(stderr, MAGENTA("[LOG]")"  | Insert new user to registered list\n");
                User *newUser = (User *)calloc(1, sizeof(User));
                newUser -> next = NULL;
                newUser -> prev = NULL;
                strcpy(newUser -> ID, inputTokens[1]);
                strcpy(newUser -> password, inputTokens[2]);
                
                pthread_mutex_lock(&registeredUsers_mutex);
                if (registeredUsers == NULL) {
                    registeredUsers = newUser;
                } else {
                    registeredUsers -> prev = newUser;
                    newUser -> next = registeredUsers;
                    registeredUsers = newUser;
                }
                pthread_mutex_unlock(&registeredUsers_mutex);
            }

            if (!userExists) {
                char sendBuffer[] = "Registration complete, please login to start using the service.\n";
                sendMessage(perClientSocket, sendBuffer);
            } else {
                fprintf(stderr, MAGENTA("[LOG]")"  | User already exists\n");
                char sendBuffer[] = "This ID has been taken, please choose another one.\n";
                sendMessage(perClientSocket, sendBuffer);
            }
            
            close(perClientSocket);
            fprintf(stderr, MAGENTA("[LOG]")"  | Connection to client %s:%d closed\n", ip_str, port);
            
            if (!userExists) {
                fprintf(stderr, MAGENTA("[LOG]")"  +-Register process complete\n");
            } else {
                fprintf(stderr, MAGENTA("[LOG]")"  +-Register failed\n");
            }
            
            break;
//MARK: - Login
        } else if (strcmp(token, "login") == 0) {
            fprintf(stderr, MAGENTA("[LOG]")" Start login process\n");
            char inputTokens[3][BUFFERSIZE] = {0}; // 1 = ID, 2 = password
            parseMessage(token, inputTokens);

            // check if user is already registered
            fprintf(stderr, MAGENTA("[LOG]")"  | Checking if user is registered\n");
            User *userRegistered = checkUserInList(&registeredUsers, inputTokens[1], &registeredUsers_mutex);

            // user not registered
            if (!userRegistered) {
                fprintf(stderr, MAGENTA("[LOG]")"  | User not registered\n");
                char sendBuffer[] = "No know user with this ID, please register first.\n";
                sendMessage(perClientSocket, sendBuffer);

                close(perClientSocket);
                fprintf(stderr, MAGENTA("[LOG]")"  | Connection to client %s:%d closed\n", ip_str, port);
                fprintf(stderr, MAGENTA("[LOG]")"  +-Login failed\n");
                break;
            }

            // user registered, check password
            fprintf(stderr, MAGENTA("[LOG]")"  | User is registered\n");
            fprintf(stderr, MAGENTA("[LOG]")"  | Checking password\n");
            if (strcmp(userRegistered -> password, inputTokens[2]) != 0) {
                fprintf(stderr, MAGENTA("[LOG]")"  | Incorrect password\n");
                char sendBuffer[] = "Incorrect password, please try again.\n";
                sendMessage(perClientSocket, sendBuffer);

                close(perClientSocket);
                fprintf(stderr, MAGENTA("[LOG]")"  | Connection to client %s:%d closed\n", ip_str, port);
                fprintf(stderr, MAGENTA("[LOG]")"  +-Login failed\n");
                break;
            }
            fprintf(stderr, MAGENTA("[LOG]")"  | Password accepted\n");
            
            // Record client listening port
            fprintf(stderr, MAGENTA("[LOG]")"  | Requesting client listening port number\n");
            char response[] = "OK.";
            sendMessage(perClientSocket, response);
            
            int32_t clientListenPort;
            read(perClientSocket, &clientListenPort, sizeof(clientListenPort));
            fprintf(stderr, MAGENTA("[LOG]")"  | Recieved client listening port number: %d\n", ntohs(clientListenPort));
            struct sockaddr_in clientListenAddress = client_address;
            clientListenAddress.sin_port = clientListenPort;
            
            // password correct, insert to logged in list
            fprintf(stderr, MAGENTA("[LOG]")"  | Inserting user to logged-in list\n");
            User *newLogin = (User *)calloc(1, sizeof(User));
            newLogin -> next = NULL;
            newLogin -> prev = NULL;
            newLogin -> address = clientListenAddress;
            strcpy(newLogin -> ID, inputTokens[1]);

            pthread_mutex_lock(&loggedInUsers_mutex);
            if (loggedInUsers == NULL) { // insert to list
                loggedInUsers = newLogin;
            } else {
                newLogin -> next = loggedInUsers;
                loggedInUsers -> prev = newLogin;
                loggedInUsers = newLogin;
            }
            pthread_mutex_unlock(&loggedInUsers_mutex);
            
            currentUser = newLogin;

            char sendBuffer[] = "Successfully logged in.\n";
            sendMessage(perClientSocket, sendBuffer);
            fprintf(stderr, MAGENTA("[LOG]")"  +-Login process complete\n");
//MARK: - List
        } else if (strcmp(token, "list") == 0) {
            fprintf(stderr, MAGENTA("[LOG]")" Start list process\n");
            
            pthread_mutex_lock(&loggedInUsers_mutex);
            User *u = loggedInUsers;
            while (u != NULL) {
                sendMessage(perClientSocket, u -> ID);
                u = u -> next;
            }
            pthread_mutex_unlock(&loggedInUsers_mutex);

            char sendBuffer[] = "END OF USER LIST";
            sendMessage(perClientSocket, sendBuffer);
            fprintf(stderr, MAGENTA("[LOG]")"  | Sent user list to client\n");
            fprintf(stderr, MAGENTA("[LOG]")"  +-List process complete\n");
        } else { // Unknown command
            char sendBuffer[] = "Unknown command.\n";
            sendMessage(perClientSocket, sendBuffer);
        }
    }
    
    return;
}

//MARK: - Threading
// Initialize job queue
static void queue_init(JobQueue *q) {
    q -> front = 0;
    q -> rear = 0;
    q -> count = 0;
    pthread_mutex_init(&q -> mutex, NULL);
    pthread_cond_init(&q -> cond_nonempty, NULL);
    pthread_cond_init(&q -> cond_nonfull, NULL);
    return;
}

// Push a socket descriptor into the job queue
static void queue_push(JobQueue *q, int sock) {
    pthread_mutex_lock(&q -> mutex);
    while (q -> count == JOB_QUEUE_SIZE) {
        pthread_cond_wait(&q -> cond_nonfull, &q -> mutex);
    }
    q -> sockets[q -> rear] = sock;
    q -> rear = (q -> rear + 1) % JOB_QUEUE_SIZE;
    q -> count++;
    pthread_cond_signal(&q -> cond_nonempty);
    pthread_mutex_unlock(&q -> mutex);
    return;
}

// Pop a socket descriptor from the job queue
static int queue_pop(JobQueue *q) {
    pthread_mutex_lock(&q -> mutex);
    while (q -> count == 0) {
        pthread_cond_wait(&q -> cond_nonempty, &q -> mutex);
    }
    int sock = q -> sockets[q -> front];
    q -> front = (q -> front + 1) % JOB_QUEUE_SIZE;
    q -> count--;
    pthread_cond_signal(&q -> cond_nonfull);
    pthread_mutex_unlock(&q -> mutex);
    return sock;
}

// Worker thread function to process client connections
static void* worker_thread(void* arg) {
    (void)arg;
    while (1) {
        int clientSock = queue_pop(&job_queue);
        handle_client(clientSock);
    }
    return NULL;
}

//MARK: - Set Socket
static int setSocket(int serverSocket) {
    struct sockaddr_in address; // IP and port number to bind the socket to
    socklen_t addrlen = sizeof(address); // length of address
    
    // Create socket file descriptor, use IPv4 and TCP
    if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror(RED("Socket creation failed\n"));
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, MAGENTA("[LOG]")" Socket created\n");

    // Attach serverSocket to the port 12000
    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror(RED("Set socket options failed\n"));
        exit(EXIT_FAILURE);
    }
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt))) {
        perror(RED("Set socket options failed\n"));
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET; // address family is IPv4
    address.sin_addr.s_addr = INADDR_ANY; // socket will be bound to all local interfaces
    address.sin_port = htons(SERVERPORT); // set port number
    if (bind(serverSocket, (struct sockaddr*)&address, addrlen) < 0) {
        perror(RED("Binding socket to port failed\n"));
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, MAGENTA("[LOG]")" Socket attached to port\n");

    // Listen for connections
    int maxWaitingToConnect = 10;
    if (listen(serverSocket, maxWaitingToConnect) < 0) {
        perror(RED("Listening for connection failed\n"));
        exit(EXIT_FAILURE);
    }
    
    return serverSocket;
}

//MARK: - Create Threads
static void createThreads(void) {
    pthread_t threads[THREAD_POOL_SIZE];
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        if (pthread_create(&threads[i], NULL, worker_thread, NULL) != 0) {
            perror(RED("Failed to create worker thread\n"));
            exit(EXIT_FAILURE);
        }
    }
    fprintf(stderr, MAGENTA("[LOG]")" Thread pool initialized\n");
    return;
}

static void sendMessage(int socket, char *buffer) {
    int32_t messageLength = htonl(strlen(buffer) + 1);
    send(socket, &messageLength, sizeof(messageLength), 0);
    send(socket, buffer, strlen(buffer) + 1, 0);
    return;
}

static void readMessage(int socket, char *buffer) {
    int32_t messageLength;
    read(socket, &messageLength, sizeof(messageLength));
    read(socket, buffer, ntohl(messageLength));
    return;
}

static void parseMessage(char *token, char (*input)[BUFFERSIZE]) {
    int parameterIndex = 0;
    while (token != NULL) {
        strcpy(input[parameterIndex], token);
        token = strtok(NULL, " ");
        parameterIndex++;
    } // tokenize input
    return;
}

static int acceptConnection(int perClientSocket, int serverSocket) {
    struct sockaddr_in address; // IP and port number to bind the socket to
    socklen_t addrlen = sizeof(address); // length of address
    if ((perClientSocket = accept(serverSocket, (struct sockaddr*)&address, &addrlen)) < 0) {
        perror(RED("Accepting connection failed\n"));
        exit(EXIT_FAILURE);
    }
    
    // Get connection details
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(address.sin_addr), ip_str, INET_ADDRSTRLEN);
    int port = ntohs(address.sin_port);  // Convert back to host byte order
    fprintf(stderr, MAGENTA("[LOG]")" Accepted client connection from %s:%d\n", ip_str, port);
    return perClientSocket;
}

static void removeFromLoggedIn(User **currentUserPtr) {
    User *currentUser = *currentUserPtr;
    pthread_mutex_lock(&loggedInUsers_mutex);
    if (loggedInUsers == currentUser) {
        loggedInUsers = currentUser -> next;
    }
    if (currentUser -> prev != NULL) {
        currentUser -> prev -> next = currentUser -> next;
    }
    if (currentUser -> next != NULL) {
        currentUser -> next -> prev = currentUser -> prev;
    }
    pthread_mutex_unlock(&loggedInUsers_mutex);
    free(currentUser);
    *currentUserPtr = NULL;
    return;
}

static User *checkUserInList(User **listHeadPtr, char *userID, pthread_mutex_t *lock) {
    pthread_mutex_lock(lock);
    User *u = *listHeadPtr;
    while (u != NULL) {
        if (strcmp(u -> ID, userID) == 0) {
            break;
        }
        u = u -> next;
    }
    pthread_mutex_unlock(lock);
    return u;
}
