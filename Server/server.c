#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <stdatomic.h>
#include <sys/stat.h>
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

#define REGLIST 0
#define LOGLIST 1

// File path to store registered users
char *registeredUserFile = "./Data/registeredUsers";

// Mutex for user list
pthread_mutex_t userList_mutex = PTHREAD_MUTEX_INITIALIZER;

// Global user lists
User *registeredUsers = NULL;
User *loggedInUsers = NULL;

// Global job queue
JobQueue job_queue;

// For server shutdown
static volatile sig_atomic_t shuttingDown = 0;
static int serverSocketGlobal = -1; // store listening socket globally

static pthread_t workerThreads[THREAD_POOL_SIZE];
static pthread_t consoleThread;

//MARK: - main
int main(int argc, char const* argv[]) {
    int serverSocket = 0, perClientSocket = 0; // Socket used for listening and socket created for each client
    
    queue_init(&job_queue); // Initialize job queue
    serverSocket = setSocket(serverSocket); // Set up server listening socket
    serverSocketGlobal = serverSocket;
    readUsers(registeredUserFile); // Read registered users from file
    createThreads(); // Create worker threads for handling clients and thread for handling shutdown
    
    while (!shuttingDown) { // Keep listening for new connections
        fprintf(stderr, MAGENTA("[LOG]")" Listening for connections\n");
        perClientSocket = acceptConnection(perClientSocket, serverSocket); // Accept connections
        if (perClientSocket < 0) {
            if (shuttingDown) {
                break; // expected during shutdown
            } else {
                continue; // or break depending on policy
            }
        }
        queue_push(&job_queue, perClientSocket); // Add accepted client socket to the job queue for worker threads
    }
    
    fprintf(stderr, YELLOW("[CONTROL]")" Stopping server, waiting for workers...\n");
    cleanUp(); // Join threads and destroy mutexes
    saveUsers(registeredUserFile); // Store registered users
    fprintf(stderr, YELLOW("[CONTROL]")" Clean up complete, exiting\n");
    
    return 0;
}

// MARK: - Chat Functions
// Handle client communication and commands
static void handle_client(int perClientSocket) {
    
    char recvBuffer[BUFFERSIZE] = {0}; // Buffer for recieving message from client
    User *currentUser = NULL; // Pointer to currently logged in user serviced by this thread
    
    // Get client address info
    struct sockaddr_in client_address;
    socklen_t client_addrlen = sizeof(client_address);
    getpeername(perClientSocket, (struct sockaddr*)&client_address, &client_addrlen);
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_address.sin_addr), ip_str, INET_ADDRSTRLEN); // Get IP
    int port = ntohs(client_address.sin_port); // Get Port
    
    while (true) { // Keep reading and processing messages from the current client
        
        readMessage(perClientSocket, recvBuffer);
        fprintf(stderr, CYAN("[MESSAGE]")" Client %s:%d: %s\n", ip_str, port, recvBuffer);
        char *token; // Pointer to store each token
        token = strtok(recvBuffer, " ");
        if (token == NULL) { // Empty command, continue reading
            continue;
        }
        
//MARK: - Logout
        if (strcmp(token, "logout") == 0) { // Client wants to disconnect
            fprintf(stderr, MAGENTA("[LOG]")" Start logout process\n");
            if (currentUser == NULL) { // No assigned current user
                fprintf(stderr, RED("[ERROR]")"| No currently logged in user\n");
                close(perClientSocket);
                break;
            }
            
            removeFromList(LOGLIST, &currentUser); // Update logged in user list
            fprintf(stderr, MAGENTA("[LOG]")"  | Removed user from logged-in list\n");
            sendMessage(perClientSocket, "Successfully logged out.\n");
            
            close(perClientSocket);
            fprintf(stderr, MAGENTA("[LOG]")"  | Connection to client %s:%d closed\n", ip_str, port);
            fprintf(stderr, MAGENTA("[LOG]")"  +-Logout process complete\n");
            break;
            
//MARK: - Register
        } else if (strcmp(token, "register") == 0) {
            fprintf(stderr, MAGENTA("[LOG]")" Start register process\n");
            char inputTokens[3][BUFFERSIZE] = {0}; // 1 = ID, 2 = password
            parseMessage(token, inputTokens);
            
            // Check if user ID is already taken
            fprintf(stderr, MAGENTA("[LOG]")"  | Checking if user exists\n");
            // Returns NULL if the user doesn't exist yet, otherwise return the pointer to the user
            User *userExists = checkUserInList(REGLIST, inputTokens[1]);
            
            if (!userExists) { // If not, create and insert new user to linked list
                fprintf(stderr, MAGENTA("[LOG]")"  | User doesn't exit\n");
                fprintf(stderr, MAGENTA("[LOG]")"  | Insert new user to registered list\n");
                if (insertUserToList(REGLIST, inputTokens[1], inputTokens[2], NULL, NULL) == NULL) {
                    fprintf(stderr, RED("[ERROR]")"| Failed to insert user\n");
                }
                sendMessage(perClientSocket, "Registration complete, please login to start using the service.\n");
            } else {
                fprintf(stderr, MAGENTA("[LOG]")"  | User already exists\n");
                sendMessage(perClientSocket, "This ID has been taken, please choose another one.\n");
            }
            
            close(perClientSocket);
            fprintf(stderr, MAGENTA("[LOG]")"  | Connection to client %s:%d closed\n", ip_str, port);
            
            if (!userExists) {
                fprintf(stderr, MAGENTA("[LOG]")"  +-Register process complete\n");
            } else {
                fprintf(stderr, MAGENTA("[LOG]")"  +-Register failed\n");
            }
            
            break;
            
//MARK: - Deregister
        } else if (strcmp(token, "deregister") == 0) {
            fprintf(stderr, MAGENTA("[LOG]")" Start deregister process\n");
            char inputTokens[2][BUFFERSIZE] = {0}; // 1 password
            parseMessage(token, inputTokens);
            
            fprintf(stderr, MAGENTA("[LOG]")"  | Checking password\n");
            if (strcmp(inputTokens[1], currentUser -> password) != 0) { // Incorrect password
                sendMessage(perClientSocket, "Incorrect password, please try again\n");
                fprintf(stderr, MAGENTA("[LOG]")"  | Incorrect password\n");
                fprintf(stderr, MAGENTA("[LOG]")"  +-Deregistration failed\n");
                continue;
            }
            
            fprintf(stderr, MAGENTA("[LOG]")"  | Password accepted, send confirmation\n");
            sendMessage(perClientSocket, "You are about to deregister, type \"yes\" to confirm.\n");
            readMessage(perClientSocket, recvBuffer);
            
            fprintf(stderr, MAGENTA("[LOG]")"  | Recieved confirmation: \"%s\"\n", recvBuffer);
            if (strcmp(recvBuffer, "yes") == 0) { // Comfirmed to deregister
                fprintf(stderr, MAGENTA("[LOG]")"  | Removing user from registered list\n");
                removeFromList(REGLIST, &currentUser); // Remove user from registered list
                fprintf(stderr, MAGENTA("[LOG]")"  | Successfully removed user from registered list\n");
                sendMessage(perClientSocket, "Successfully deregistered.\n");
                
                close(perClientSocket);
                fprintf(stderr, MAGENTA("[LOG]")"  | Connection to client %s:%d closed\n", ip_str, port);
                fprintf(stderr, MAGENTA("[LOG]")"  +-Deregistration complete\n");
                break;
            } else { // Don't deregister
                sendMessage(perClientSocket, "Deregistration canceled.\n");
                fprintf(stderr, MAGENTA("[LOG]")"  +-Deregistration canceled\n");
            }
            
//MARK: - Login
        } else if (strcmp(token, "login") == 0) {
            fprintf(stderr, MAGENTA("[LOG]")" Start login process\n");
            char inputTokens[3][BUFFERSIZE] = {0}; // 1 = ID, 2 = password
            parseMessage(token, inputTokens);
            
            // Check if user is already registered
            fprintf(stderr, MAGENTA("[LOG]")"  | Checking if user is registered\n");
            // Returns NULL if the user doesn't exist yet, otherwise return the pointer to the user
            User *userRegistered = checkUserInList(REGLIST, inputTokens[1]);
            
            // User not registered
            if (!userRegistered) {
                fprintf(stderr, MAGENTA("[LOG]")"  | User not registered\n");
                sendMessage(perClientSocket, "No know user with this ID, please register first.\n");
                
                close(perClientSocket);
                fprintf(stderr, MAGENTA("[LOG]")"  | Connection to client %s:%d closed\n", ip_str, port);
                fprintf(stderr, MAGENTA("[LOG]")"  +-Login failed\n");
                break;
            }
            
            // User registered, check password
            fprintf(stderr, MAGENTA("[LOG]")"  | User is registered\n");
            fprintf(stderr, MAGENTA("[LOG]")"  | Checking password\n");
            if (strcmp(userRegistered -> password, inputTokens[2]) != 0) {
                fprintf(stderr, MAGENTA("[LOG]")"  | Incorrect password\n");
                sendMessage(perClientSocket, "Incorrect password, please try again.\n");
                
                close(perClientSocket);
                fprintf(stderr, MAGENTA("[LOG]")"  | Connection to client %s:%d closed\n", ip_str, port);
                fprintf(stderr, MAGENTA("[LOG]")"  +-Login failed\n");
                break;
            }
            fprintf(stderr, MAGENTA("[LOG]")"  | Password accepted\n");
            
            // Password correct, get client listening port
            fprintf(stderr, MAGENTA("[LOG]")"  | Requesting client listening port number\n");
            sendMessage(perClientSocket, "OK.");
            
            int32_t clientListenPort;
            read(perClientSocket, &clientListenPort, sizeof(clientListenPort));
            fprintf(stderr, MAGENTA("[LOG]")"  | Recieved client listening port number: %d\n", ntohs(clientListenPort));
            struct sockaddr_in clientListenAddress = client_address;
            clientListenAddress.sin_port = clientListenPort;
            
            // Insert user to logged in list
            fprintf(stderr, MAGENTA("[LOG]")"  | Inserting user to logged-in list\n");
            // Returns the newly created user entry
            currentUser = insertUserToList(LOGLIST, NULL, NULL, &clientListenAddress, &userRegistered);
            if (currentUser == NULL) { // Fail to insert
                fprintf(stderr, RED("[ERROR]")"| Failed to insert user\n");
                sendMessage(perClientSocket, "Error logging in.\n");
                
                close(perClientSocket);
                fprintf(stderr, MAGENTA("[LOG]")"  | Connection to client %s:%d closed\n", ip_str, port);
                fprintf(stderr, MAGENTA("[LOG]")"  +-Login failed\n");
                break;
            }
            
            sendMessage(perClientSocket, "Successfully logged in.\n");
            fprintf(stderr, MAGENTA("[LOG]")"  +-Login process complete\n");
            
//MARK: - List
        } else if (strcmp(token, "list") == 0) {
            fprintf(stderr, MAGENTA("[LOG]")" Start list process\n");
            
            // Send the logged in list to client
            pthread_mutex_lock(&userList_mutex);
            User *u = loggedInUsers;
            while (u != NULL) {
                sendMessage(perClientSocket, u -> ID);
                u = u -> logNext;
            }
            pthread_mutex_unlock(&userList_mutex);
            
            sendMessage(perClientSocket, "END OF USER LIST");
            fprintf(stderr, MAGENTA("[LOG]")"  | Sent user list to client\n");
            fprintf(stderr, MAGENTA("[LOG]")"  +-List process complete\n");
           
//MARK: - DM
        } else if (strcmp(token, "chat") == 0) {
            fprintf(stderr, MAGENTA("[LOG]")" Start chat process\n");
            char inputTokens[2][BUFFERSIZE] = {0}; // 1 = peer ID
            parseMessage(token, inputTokens);
            
            fprintf(stderr, MAGENTA("[LOG]")"  | Checking if target peer is online\n");
            User *target = checkUserInList(LOGLIST, inputTokens[1]); // Retrieve target user
            if (target == NULL) { // Target not online
                sendMessage(perClientSocket, "Peer currently offline.\n");
                fprintf(stderr, MAGENTA("[LOG]")"  | Target peer offline or does noot exist\n");
                fprintf(stderr, MAGENTA("[LOG]")"  +-Chat failed\n");
                continue;
            }
            
            fprintf(stderr, MAGENTA("[LOG]")"  | Target peer online, sending connection info\n");
            sendMessage(perClientSocket, "OK.");
            send(perClientSocket, &(target -> address.sin_addr.s_addr), sizeof(in_addr_t), 0); // Send IP address
            send(perClientSocket, &(target -> address.sin_port), sizeof(in_port_t), 0); // Send port number
            
            fprintf(stderr, MAGENTA("[LOG]")"  +-Sent, keeping connection to client for next command\n");
            // close connection???
        } else { // Unknown command
            sendMessage(perClientSocket, "Unknown command.\n");
        }
    } // End of while loop
    
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
    while (q -> count == 0 && !shuttingDown) {
        pthread_cond_wait(&q -> cond_nonempty, &q -> mutex);
    }
    
    if (q->count == 0 && shuttingDown) { // Shutdown
        pthread_mutex_unlock(&q->mutex);
        return -1; // sentinel to tell workers to exit
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
        if (clientSock < 0) { // Shutdown
            break;
        }
        handle_client(clientSock);
    }
    return NULL;
}

static void *consoleWatcher(void *arg) {
    char line[128];
    while (fgets(line, sizeof line, stdin)) {
        if (strncmp(line, "quit", 4) == 0 || strncmp(line, "exit", 4) == 0 || strncmp(line, "shutdown", 8) == 0) {
            fprintf(stderr, YELLOW("[CONTROL]")" Shutdown requested from console\n");
            shuttingDown = 1;
            // Close the listening socket to unblock accept()
            if (serverSocketGlobal >= 0) {
                close(serverSocketGlobal);
                serverSocketGlobal = -1;
            }
            break;
        } else if (strncmp(line, "list", 4) == 0) { // List registered users
            fprintf(stderr, YELLOW("[CONTROL]")" Listing registered users:\n");
            pthread_mutex_lock(&userList_mutex);
            User *u = registeredUsers;
            while (u != NULL) {
                fprintf(stderr, YELLOW("[CONTROL]")" %s\n", u -> ID);
                u = u -> regNext;
            }
            pthread_mutex_unlock(&userList_mutex);
            fprintf(stderr, YELLOW("[CONTROL]")" End of list\n");
        }
    }
    return NULL;
}

static void cleanUp(void) {
    // Wake any waiting workers in case not already woken
    pthread_mutex_lock(&job_queue.mutex);
    pthread_cond_broadcast(&job_queue.cond_nonempty);
    pthread_cond_broadcast(&job_queue.cond_nonfull);
    pthread_mutex_unlock(&job_queue.mutex);
    
    // Join worker threads
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        if (workerThreads[i]) {
            pthread_join(workerThreads[i], NULL);
        }
    }
    // Join console watcher thread
    pthread_join(consoleThread, NULL);
    fprintf(stderr, MAGENTA("[LOG]")" Joined all threads\n");
    
    // Destroy job queue synchronization primitives
    pthread_mutex_destroy(&job_queue.mutex);
    pthread_cond_destroy(&job_queue.cond_nonempty);
    pthread_cond_destroy(&job_queue.cond_nonfull);
    
    // Destroy user list mutexes
    pthread_mutex_destroy(&userList_mutex);
    fprintf(stderr, MAGENTA("[LOG]")" Destroyed mutex\n");
}

//MARK: - Set Socket
static int setSocket(int serverSocket) {
    struct sockaddr_in address; // IP and port number to bind the socket to
    socklen_t addrlen = sizeof(address); // length of address
    
    // Create socket file descriptor, use IPv4 and TCP
    if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror(RED("[ERROR]")" Socket creation failed\n");
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, MAGENTA("[LOG]")" Socket created\n");
    
    // Attach serverSocket to the port 12000
    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror(RED("[ERROR]")" Set socket options failed\n");
        exit(EXIT_FAILURE);
    }
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt))) {
        perror(RED("[ERROR]")" Set socket options failed\n");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET; // address family is IPv4
    address.sin_addr.s_addr = INADDR_ANY; // socket will be bound to all local interfaces
    address.sin_port = htons(SERVERPORT); // set port number
    if (bind(serverSocket, (struct sockaddr*)&address, addrlen) < 0) {
        perror(RED("[ERROR]")" Binding socket to port failed\n");
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, MAGENTA("[LOG]")" Socket attached to port\n");
    
    // Listen for connections
    int maxWaitingToConnect = 10;
    if (listen(serverSocket, maxWaitingToConnect) < 0) {
        perror(RED("[ERROR]")" Listening for connection failed\n");
        exit(EXIT_FAILURE);
    }
    
    return serverSocket;
}

//MARK: - Create Threads
static void createThreads(void) {
    // Create watcher thread for shutdown command
    if (pthread_create(&consoleThread, NULL, consoleWatcher, NULL) != 0) {
        perror(RED("[ERROR]")" Failed to create console watcher thread\n");
        exit(EXIT_FAILURE);
    }
    
    // Create threads for servicing client connections
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        if (pthread_create(&workerThreads[i], NULL, worker_thread, NULL) != 0) {
            perror(RED("[ERROR]")" Failed to create worker thread\n");
            exit(EXIT_FAILURE);
        }
    }
    fprintf(stderr, MAGENTA("[LOG]")" Thread pool initialized\n");
    return;
}

//MARK: - Other Helpers
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
        if (input != NULL) {
            strcpy(input[parameterIndex], token);
        }
        token = strtok(NULL, " ");
        parameterIndex++;
    } // tokenize input
    return;
}

static int acceptConnection(int perClientSocket, int serverSocket) {
    struct sockaddr_in address; // IP and port number to bind the socket to
    socklen_t addrlen = sizeof(address); // length of address
    if ((perClientSocket = accept(serverSocket, (struct sockaddr*)&address, &addrlen)) < 0) {
        if (shuttingDown) { // Listening socket closed on purpose
            fprintf(stderr, MAGENTA("[LOG]")" Accept interrupted by shutdown\n");
        } else {
            fprintf(stderr, RED("[ERROR]")" Accepting connection failed\n");
        }
        return -1;
    }
    
    // Get connection details
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(address.sin_addr), ip_str, INET_ADDRSTRLEN);
    int port = ntohs(address.sin_port);  // Convert back to host byte order
    fprintf(stderr, MAGENTA("[LOG]")" Accepted client connection from %s:%d\n", ip_str, port);
    return perClientSocket;
}

static void removeFromList(bool mode, User **currentUserPtr) {
    User *currentUser = *currentUserPtr;
    
    if (mode == REGLIST) { // Deregister
        // remove from registered list
        pthread_mutex_lock(&userList_mutex);
        if (registeredUsers == currentUser) {
            registeredUsers = currentUser -> regNext;
        }
        if (currentUser -> regPrev != NULL) {
            currentUser -> regPrev -> regNext = currentUser -> regNext;
        }
        if (currentUser -> regNext != NULL) {
            currentUser -> regNext -> regPrev = currentUser -> regPrev;
        }
        
        // Remove from logged in list
        if (loggedInUsers == currentUser) {
            loggedInUsers = currentUser -> logNext;
        }
        if (currentUser -> logPrev != NULL) {
            currentUser -> logPrev -> logNext = currentUser -> logNext;
        }
        if (currentUser -> logNext != NULL) {
            currentUser -> logNext -> logPrev = currentUser -> logPrev;
        }
        pthread_mutex_unlock(&userList_mutex);
        
        free(currentUser);
    } else if (mode == LOGLIST) { // Logout only
        // Remove from logged in list
        pthread_mutex_lock(&userList_mutex);
        if (loggedInUsers == currentUser) {
            loggedInUsers = currentUser -> logNext;
        }
        if (currentUser -> logPrev != NULL) {
            currentUser -> logPrev -> logNext = currentUser -> logNext;
        }
        if (currentUser -> logNext != NULL) {
            currentUser -> logNext -> logPrev = currentUser -> logPrev;
        }
        pthread_mutex_unlock(&userList_mutex);
    }
    
    *currentUserPtr = NULL;
    return;
}

static User *checkUserInList(bool mode, char *userID) {
    User *u = NULL;
    if (mode == REGLIST) {
        pthread_mutex_lock(&userList_mutex);
        u = registeredUsers;
        while (u != NULL) {
            if (strcmp(u -> ID, userID) == 0) {
                break;
            }
            u = u -> regNext;
        }
        pthread_mutex_unlock(&userList_mutex);
    } else if (mode == LOGLIST) {
        pthread_mutex_lock(&userList_mutex);
        u = loggedInUsers;
        while (u != NULL) {
            if (strcmp(u -> ID, userID) == 0) {
                break;
            }
            u = u -> logNext;
        }
        pthread_mutex_unlock(&userList_mutex);
    }
    
    return u;
}

static User *insertUserToList(bool mode, char *userID, char *password, struct sockaddr_in *clientListenAddress, User **loginUser) {
    User *inserted = NULL;
    if (mode == REGLIST) { // Insert to registeredUsers
        inserted = (User *)calloc(1, sizeof(User));
        inserted -> regNext = NULL;
        inserted -> regPrev = NULL;
        inserted -> logNext = NULL;
        inserted -> logPrev = NULL;
        strcpy(inserted -> ID, userID);
        strcpy(inserted -> password, password);
        
        pthread_mutex_lock(&userList_mutex);
        if (registeredUsers == NULL) {
            registeredUsers = inserted;
        } else {
            registeredUsers -> regPrev = inserted;
            inserted -> regNext = registeredUsers;
            registeredUsers = inserted;
        }
        pthread_mutex_unlock(&userList_mutex);
    } else if (mode == LOGLIST) { // Insert to loggedInUsers
        inserted = *loginUser;
        
        pthread_mutex_lock(&userList_mutex);
        inserted -> address = *clientListenAddress;
        if (loggedInUsers == NULL) { // insert to list
            loggedInUsers = inserted;
        } else {
            inserted -> logNext = loggedInUsers;
            loggedInUsers -> logPrev = inserted;
            loggedInUsers = inserted;
        }
        pthread_mutex_unlock(&userList_mutex);
    }
    
    return inserted;
}

static void saveUsers(char *fileName) {
    FILE *file = fopen(fileName, "wb");
    if (!file) {
        perror(RED("[ERROR]")" Failed to open file to save registered users\n");
        return;
    }
    
    User *delete, *u = registeredUsers;
    while (u != NULL) {
        // Write the ID, password, and sockaddr_in
        fwrite(u -> ID, sizeof(char), BUFFERSIZE, file);
        fwrite(u -> password, sizeof(char), BUFFERSIZE, file);
        delete = u;
        u = u -> regNext;
        free(delete);
    }
    
    fclose(file);
    fprintf(stderr, MAGENTA("[LOG]")" Stored and freed registered user list\n");
    return;
}

static void readUsers(char *fileName) {
    if (!directoryExists("./Data")) {
        mkdir("./Data", 0755);
    }
    
    FILE *file = fopen(fileName, "a+b");
    if (!file) {
        perror(RED("[ERROR]")" Failed to open file to read registered users\n");
        return;
    }
    fseek(file, 0, SEEK_SET);
    
    while (1) {
        User *newUser = malloc(sizeof(User));
        if (!newUser) {
            perror(RED("[ERROR]")" malloc failed\n");
            break;
        }
        
        // Read ID
        if (fread(newUser -> ID, sizeof(char), BUFFERSIZE, file) != BUFFERSIZE) {
            break;
        }
        // Read password
        fread(newUser -> password, sizeof(char), BUFFERSIZE, file);
        
        newUser -> regNext = NULL;
        newUser -> regPrev = NULL;
        newUser -> logNext = NULL;
        newUser -> logPrev = NULL;
        
        if (registeredUsers == NULL) {
            registeredUsers = newUser;
        } else {
            newUser -> regNext = registeredUsers;
            registeredUsers -> regPrev = newUser;
            registeredUsers = newUser;
        }
    }
    
    fclose(file);
    fprintf(stderr, MAGENTA("[LOG]")" Read registered user list from file\n");
    return;
}

static int directoryExists(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        return S_ISDIR(st.st_mode);  // true if it's a directory
    }
    return 0;  // stat() failed → doesn't exist (or can't be accessed)
}
