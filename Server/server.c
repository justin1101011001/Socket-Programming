#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdatomic.h>
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

// Mutexes for user lists
pthread_mutex_t registeredUsers_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t loggedInUsers_mutex = PTHREAD_MUTEX_INITIALIZER;

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

int main(int argc, char const* argv[]) {
    //MARK: - main
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
        if (token == NULL) {
            // Empty command, continue reading
            continue;
        }
        
        //MARK: - Logout
        if (strcmp(token, "logout") == 0) { // Client wants to disconnect
            fprintf(stderr, MAGENTA("[LOG]")" Start logout process\n");
            if (currentUser != NULL) {
                removeFromList(LOGLIST, &currentUser); // Update logged in user list
                fprintf(stderr, MAGENTA("[LOG]")"  | Removed user from logged-in list\n");
            }
            
            char sendBuffer[] = "Successfully logged out.\n";
            sendMessage(perClientSocket, sendBuffer);
            
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
            User *userExists = checkUserInList(&registeredUsers, inputTokens[1], &registeredUsers_mutex);
            // Returns NULL if the user doesn't exist yet, otherwise return the pointer to the user
            
            if (!userExists) { // If not, create and insert new user to linked list
                fprintf(stderr, MAGENTA("[LOG]")"  | User doesn't exit\n");
                fprintf(stderr, MAGENTA("[LOG]")"  | Insert new user to registered list\n");
                createAndInsertUserToList(REGLIST, inputTokens[1], inputTokens[2], NULL);
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
            //MARK: - Deregister
        } else if (strcmp(token, "deregister") == 0) {
            fprintf(stderr, MAGENTA("[LOG]")" Start deregister process\n");
            char inputTokens[2][BUFFERSIZE] = {0}; // 1 password
            parseMessage(token, inputTokens);
            
            fprintf(stderr, MAGENTA("[LOG]")"  | Checking password\n");
            if (strcmp(inputTokens[1], currentUser -> password) != 0) { // Incorrect password
                char sendBuffer[] = "Incorrect password, please try again\n";
                sendMessage(perClientSocket, sendBuffer);
                fprintf(stderr, MAGENTA("[LOG]")"  | Incorrect password\n");
                fprintf(stderr, MAGENTA("[LOG]")"  +-Deregistration failed\n");
                continue;
            }
            
            fprintf(stderr, MAGENTA("[LOG]")"  | Password accepted, send confirmation\n");
            char comfirmation[] = "You are about to deregister, type \"yes\" to confirm.\n";
            sendMessage(perClientSocket, comfirmation);
            readMessage(perClientSocket, recvBuffer);
            
            fprintf(stderr, MAGENTA("[LOG]")"  | Recieved confirmation: \"%s\"\n", recvBuffer);
            if (strcmp(recvBuffer, "yes") == 0) { // Comfirmed to deregister
                fprintf(stderr, MAGENTA("[LOG]")"  | Removing user from registered list\n");
                removeFromList(REGLIST, &currentUser); // Remove user from registered list
                fprintf(stderr, MAGENTA("[LOG]")"  | Successfully removed user from registered list\n");
                char sendBuffer[] = "Successfully deregistered.\n";
                sendMessage(perClientSocket, sendBuffer);
                
                close(perClientSocket);
                fprintf(stderr, MAGENTA("[LOG]")"  | Connection to client %s:%d closed\n", ip_str, port);
                fprintf(stderr, MAGENTA("[LOG]")"  +-Deregistration complete\n");
                break;
            } else { // Don't deregister
                char sendBuffer[] = "Deregistration canceled.\n";
                sendMessage(perClientSocket, sendBuffer);
                fprintf(stderr, MAGENTA("[LOG]")"  +-Deregistration canceled\n");
            }
            
            //MARK: - Login
        } else if (strcmp(token, "login") == 0) {
            fprintf(stderr, MAGENTA("[LOG]")" Start login process\n");
            char inputTokens[3][BUFFERSIZE] = {0}; // 1 = ID, 2 = password
            parseMessage(token, inputTokens);
            
            // Check if user is already registered
            fprintf(stderr, MAGENTA("[LOG]")"  | Checking if user is registered\n");
            User *userRegistered = checkUserInList(&registeredUsers, inputTokens[1], &registeredUsers_mutex);
            // Returns NULL if the user doesn't exist yet, otherwise return the pointer to the user
            
            // User not registered
            if (!userRegistered) {
                fprintf(stderr, MAGENTA("[LOG]")"  | User not registered\n");
                char sendBuffer[] = "No know user with this ID, please register first.\n";
                sendMessage(perClientSocket, sendBuffer);
                
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
                char sendBuffer[] = "Incorrect password, please try again.\n";
                sendMessage(perClientSocket, sendBuffer);
                
                close(perClientSocket);
                fprintf(stderr, MAGENTA("[LOG]")"  | Connection to client %s:%d closed\n", ip_str, port);
                fprintf(stderr, MAGENTA("[LOG]")"  +-Login failed\n");
                break;
            }
            fprintf(stderr, MAGENTA("[LOG]")"  | Password accepted\n");
            
            // Password correct, get client listening port
            fprintf(stderr, MAGENTA("[LOG]")"  | Requesting client listening port number\n");
            char response[] = "OK.";
            sendMessage(perClientSocket, response);
            
            int32_t clientListenPort;
            read(perClientSocket, &clientListenPort, sizeof(clientListenPort));
            fprintf(stderr, MAGENTA("[LOG]")"  | Recieved client listening port number: %d\n", ntohs(clientListenPort));
            struct sockaddr_in clientListenAddress = client_address;
            clientListenAddress.sin_port = clientListenPort;
            
            sendMessage(perClientSocket, inputTokens[1]); // Send back user ID
            
            // Create and insert user to logged in list
            fprintf(stderr, MAGENTA("[LOG]")"  | Inserting user to logged-in list\n");
            currentUser = createAndInsertUserToList(LOGLIST, inputTokens[1], inputTokens[2], &clientListenAddress);
            // Returns the newly created user entry
            
            char sendBuffer[] = "Successfully logged in.\n";
            sendMessage(perClientSocket, sendBuffer);
            fprintf(stderr, MAGENTA("[LOG]")"  +-Login process complete\n");
            //MARK: - List
        } else if (strcmp(token, "list") == 0) {
            fprintf(stderr, MAGENTA("[LOG]")" Start list process\n");
            
            // Send the logged in list to client
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
    pthread_mutex_destroy(&registeredUsers_mutex);
    pthread_mutex_destroy(&loggedInUsers_mutex);
    fprintf(stderr, MAGENTA("[LOG]")" Destroyed mutexes\n");
    
    // Free logged in user list
    User *u;
    while (loggedInUsers != NULL) {
        u = loggedInUsers;
        loggedInUsers = loggedInUsers -> next;
        free(u);
    }
    fprintf(stderr, MAGENTA("[LOG]")" Freed logged in user list\n");
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
    
    if (mode == REGLIST) { // remove from registered list
        User *registered = checkUserInList(&registeredUsers, currentUser -> ID, &registeredUsers_mutex); // Find user in registered list
        if (registered == NULL) {
            fprintf(stderr, RED("[ERROR]")" User not found in registered list\n");
        } else {
            pthread_mutex_lock(&registeredUsers_mutex);
            if (registeredUsers == registered) {
                registeredUsers = registered -> next;
            }
            if (registered -> prev != NULL) {
                registered -> prev -> next = registered -> next;
            }
            if (registered -> next != NULL) {
                registered -> next -> prev = registered -> prev;
            }
            pthread_mutex_unlock(&registeredUsers_mutex);
            
            free(registered);
        }
    }
    
    // Remove from logged in list
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

static User *createAndInsertUserToList(bool mode, char *userID, char *password, struct sockaddr_in *clientListenAddress) {
    User *inserted = (User *)calloc(1, sizeof(User));
    inserted -> next = NULL;
    inserted -> prev = NULL;
    
    if (mode == REGLIST) { // Insert to registeredUsers
        strcpy(inserted -> ID, userID);
        strcpy(inserted -> password, password);
        
        pthread_mutex_lock(&registeredUsers_mutex);
        if (registeredUsers == NULL) {
            registeredUsers = inserted;
        } else {
            registeredUsers -> prev = inserted;
            inserted -> next = registeredUsers;
            registeredUsers = inserted;
        }
        pthread_mutex_unlock(&registeredUsers_mutex);
    } else if (mode == LOGLIST) { // Insert to loggedInUsers
        strcpy(inserted -> ID, userID);
        strcpy(inserted -> password, password);
        inserted -> address = *clientListenAddress;
        
        pthread_mutex_lock(&loggedInUsers_mutex);
        if (loggedInUsers == NULL) { // insert to list
            loggedInUsers = inserted;
        } else {
            inserted -> next = loggedInUsers;
            loggedInUsers -> prev = inserted;
            loggedInUsers = inserted;
        }
        pthread_mutex_unlock(&loggedInUsers_mutex);
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
        fwrite(&(u -> address), sizeof(struct sockaddr_in), 1, file);
        delete = u;
        u = u -> next;
        free(delete);
    }
    
    fclose(file);
    fprintf(stderr, MAGENTA("[LOG]")" Stored and freed registered user list\n");
    return;
}

static void readUsers(char *fileName) {
    FILE *file = fopen(fileName, "rb");
    if (!file) {
        perror(RED("[ERROR]")" Failed to open file to read registered users\n");
        return;
    }
    
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
        // Read address
        fread(&(newUser -> address), sizeof(struct sockaddr_in), 1, file);
        
        newUser -> next = NULL;
        newUser -> prev = NULL;
        
        if (registeredUsers == NULL) {
            registeredUsers = newUser;
        } else {
            newUser -> next = registeredUsers;
            registeredUsers -> prev = newUser;
            registeredUsers = newUser;
        }
    }
    
    fclose(file);
    fprintf(stderr, MAGENTA("[LOG]")" Read registered user list from file\n");
    return;
}
