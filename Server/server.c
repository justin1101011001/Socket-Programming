#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#define SERVERPORT 12014
#define BUFFERSIZE 1024
#define THREAD_POOL_SIZE 10
#define JOB_QUEUE_SIZE 16

// User structure
typedef struct userClient {
    char ID[BUFFERSIZE];
    char password[BUFFERSIZE];
    struct sockaddr_in address;
    struct userClient *next;
    struct userClient *prev;
} User;

// Job queue for client socket descriptors
typedef struct {
    int sockets[JOB_QUEUE_SIZE];
    int front, rear, count;
    pthread_mutex_t mutex;
    pthread_cond_t cond_nonempty;
    pthread_cond_t cond_nonfull;
} JobQueue;

// Mutexes for user lists
pthread_mutex_t registeredUsers_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t loggedInUsers_mutex = PTHREAD_MUTEX_INITIALIZER;

// Global user lists
User *registeredUsers = NULL;
User *loggedInUsers = NULL;

// Global job queue
JobQueue job_queue;

//MARK: - Threading
// Initialize job queue
void queue_init(JobQueue *q) {
    q -> front = 0;
    q -> rear = 0;
    q -> count = 0;
    pthread_mutex_init(&q -> mutex, NULL);
    pthread_cond_init(&q -> cond_nonempty, NULL);
    pthread_cond_init(&q -> cond_nonfull, NULL);
}

// Push a socket descriptor into the job queue
void queue_push(JobQueue *q, int sock) {
    pthread_mutex_lock(&q -> mutex);
    while (q -> count == JOB_QUEUE_SIZE) {
        pthread_cond_wait(&q -> cond_nonfull, &q -> mutex);
    }
    q -> sockets[q -> rear] = sock;
    q -> rear = (q -> rear + 1) % JOB_QUEUE_SIZE;
    q -> count++;
    pthread_cond_signal(&q -> cond_nonempty);
    pthread_mutex_unlock(&q -> mutex);
}

// Pop a socket descriptor from the job queue
int queue_pop(JobQueue *q) {
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

// Handle client communication and commands
static void handle_client(int perClientSocket) {
    char buffer[BUFFERSIZE] = {0};
    ssize_t readVal;
    User *currentUser = NULL;

    // Get client address info
    struct sockaddr_in client_address;
    socklen_t client_addrlen = sizeof(client_address);
    getpeername(perClientSocket, (struct sockaddr*)&client_address, &client_addrlen);
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_address.sin_addr), ip_str, INET_ADDRSTRLEN); // IP
    int port = ntohs(client_address.sin_port); // Port

    while (true) { // keep reading and processing messages from the current client
        memset(buffer, 0, sizeof(buffer)); // clear buffer
        readVal = read(perClientSocket, buffer, BUFFERSIZE);
        if (readVal <= 0) {
            // Client closed connection or error
            if (currentUser != NULL) {
                // Logout user on unexpected disconnect
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
                currentUser = NULL;
            }
            close(perClientSocket);
            break;
        }

        fprintf(stderr, "\033[36m[MESSAGE]\033[0m Client %s:%d: %s\n", ip_str, port, buffer);

        char *token; // Pointer to store each token
        token = strtok(buffer, " ");
        if (token == NULL) {
            // Empty command, continue reading
            continue;
        }

//MARK: - Logout
        if (strcmp(token, "logout") == 0) { // client wants to disconnect
            fprintf(stderr, "\033[35m[LOG]\033[0m Start logout process\n");
            if (currentUser != NULL) {
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
                currentUser = NULL;
                fprintf(stderr, "\033[35m[LOG]\033[0m  | Removed user from logged-in list\n");
            }

            char sendBuffer[] = "Successfully logged out.\n";
            send(perClientSocket, sendBuffer, strlen(sendBuffer), 0);

            // Close connection
            close(perClientSocket);
            fprintf(stderr, "\033[35m[LOG]\033[0m  | Connection to client %s:%d closed\n", ip_str, port);
            fprintf(stderr, "\033[35m[LOG]\033[0m Logout process complete\n");
            break;
//MARK: - Register
        } else if (strcmp(token, "register") == 0) { // registration
            fprintf(stderr, "\033[35m[LOG]\033[0m Start register process\n");
            char inputTokens[3][BUFFERSIZE] = {0}; // 1 = ID, 2 = password
            int parameterIndex = 0;
            while (token != NULL) {
                strcpy(inputTokens[parameterIndex], token);
                token = strtok(NULL, " ");
                parameterIndex++;
            } // tokenize input

            // check if user ID is already taken
            fprintf(stderr, "\033[35m[LOG]\033[0m  | Checking if user exists\n");
            bool userExists = false;
            pthread_mutex_lock(&registeredUsers_mutex);
            User *u = registeredUsers;
            while (u != NULL) {
                if (strcmp(u -> ID, inputTokens[1]) == 0) {
                    userExists = true;
                    break;
                }
                u = u -> next;
            }

            if (!userExists) { // if not, insert new user to linked list
                fprintf(stderr, "\033[35m[LOG]\033[0m  | User doesn't exit\n");
                fprintf(stderr, "\033[35m[LOG]\033[0m  | Insert new user to registered list\n");
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
            }
            pthread_mutex_unlock(&registeredUsers_mutex);

            if (!userExists) {
                char completionMessage[] = "Registration complete, please login to start using the service.\n";
                send(perClientSocket, completionMessage, strlen(completionMessage), 0);
            } else {
                fprintf(stderr, "\033[35m[LOG]\033[0m  | User already exists\n");
                char errorMessage[] = "This ID has been taken, please choose another one.\n";
                send(perClientSocket, errorMessage, strlen(errorMessage), 0);
            }

            // Close connection
            close(perClientSocket);
            fprintf(stderr, "\033[35m[LOG]\033[0m  | Connection to client %s:%d closed\n", ip_str, port);
            fprintf(stderr, "\033[35m[LOG]\033[0m Register process complete\n");
            break;
//MARK: - Login
        } else if (strcmp(token, "login") == 0) {
            fprintf(stderr, "\033[35m[LOG]\033[0m Start login process\n");
            char inputTokens[3][BUFFERSIZE] = {0}; // 1 = ID, 2 = password
            int parameterIndex = 0;
            while (token != NULL) {
                strcpy(inputTokens[parameterIndex], token);
                token = strtok(NULL, " ");
                parameterIndex++;
            } // tokenize input

            // check if user is already registered
            fprintf(stderr, "\033[35m[LOG]\033[0m  | Checking if user is registered\n");
            bool userRegistered = false;
            User *u = NULL;

            pthread_mutex_lock(&registeredUsers_mutex);
            u = registeredUsers;
            while (u != NULL) {
                if (strcmp(u -> ID, inputTokens[1]) == 0) {
                    userRegistered = true;
                    break;
                }
                u = u -> next;
            }
            pthread_mutex_unlock(&registeredUsers_mutex);

            // user not registered
            if (!userRegistered) {
                fprintf(stderr, "\033[35m[LOG]\033[0m  | User not registered\n");
                char errorMessage[] = "No know user with this ID, please register first.\n";
                send(perClientSocket, errorMessage, strlen(errorMessage), 0);

                // Close the connected socket
                close(perClientSocket);
                fprintf(stderr, "\033[35m[LOG]\033[0m  | Connection to client %s:%d closed\n", ip_str, port);
                fprintf(stderr, "\033[35m[LOG]\033[0m Login failed\n");
                break;
            }

            // user registered, check password
            fprintf(stderr, "\033[35m[LOG]\033[0m  | User is registered\n");
            fprintf(stderr, "\033[35m[LOG]\033[0m  | Checking password\n");
            if (strcmp(u -> password, inputTokens[2]) != 0) {
                fprintf(stderr, "\033[35m[LOG]\033[0m |  Incorrect password\n");
                char errorMessage[] = "Incorrect password, please try again.\n";
                send(perClientSocket, errorMessage, strlen(errorMessage), 0);

                // Close connection
                close(perClientSocket);
                fprintf(stderr, "\033[35m[LOG]\033[0m  | Connection to client %s:%d closed\n", ip_str, port);
                fprintf(stderr, "\033[35m[LOG]\033[0m Login failed\n");
                break;
            }

            
            fprintf(stderr, "\033[35m[LOG]\033[0m  | Password accepted\n");
            
            // Record client listening port
            fprintf(stderr, "\033[35m[LOG]\033[0m  | Requesting client listening port number\n");
            char response[] = "OK.";
            send(perClientSocket, response, BUFFERSIZE, 0);
            int32_t clientListenPort;
            readVal = read(perClientSocket, &clientListenPort, BUFFERSIZE);
            fprintf(stderr, "\033[35m[LOG]\033[0m  | Recieved client listening port number: %d\n", ntohs(clientListenPort));
            struct sockaddr_in clientListenAddress = client_address;
            clientListenAddress.sin_port = clientListenPort;
            
            // password correct, insert to logged in list
            fprintf(stderr, "\033[35m[LOG]\033[0m  | Inserting user to logged-in list\n");
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

            char completionMessage[] = "Successfully logged in.\n";
            send(perClientSocket, completionMessage, BUFFERSIZE, 0);
            fprintf(stderr, "\033[35m[LOG]\033[0m Login process complete\n");
//MARK: - List
        } else if (strcmp(token, "list") == 0) {
            fprintf(stderr, "\033[35m[LOG]\033[0m Start list process\n");
            pthread_mutex_lock(&loggedInUsers_mutex);
            User *u = loggedInUsers;
            while (u != NULL) {
                send(perClientSocket, u -> ID, BUFFERSIZE, 0);
                u = u -> next;
            }
            pthread_mutex_unlock(&loggedInUsers_mutex);

            char completionMessage[] = "END OF USER LIST";
            send(perClientSocket, completionMessage, BUFFERSIZE, 0);
            fprintf(stderr, "\033[35m[LOG]\033[0m  | Sent user list to client\n");
            fprintf(stderr, "\033[35m[LOG]\033[0m List process complete\n");
        } else {
            // Unknown command
            char errorMessage[] = "Unknown command.\n";
            send(perClientSocket, errorMessage, strlen(errorMessage), 0);
        }
    }
}

// Worker thread function to process client connections
void* worker_thread(void* arg) {
    (void)arg;
    while (1) {
        int clientSock = queue_pop(&job_queue);
        handle_client(clientSock);
    }
    return NULL;
}

int main(int argc, char const* argv[]) {
//MARK: - main
    int serverSocket, perClientSocket; // socket used for listening and socket created for each client
    struct sockaddr_in address; // IP and port number to bind the socket to
    socklen_t addrlen = sizeof(address); // length of address

    // Initialize job queue
    queue_init(&job_queue);

    // Create socket file descriptor, use IPv4 and TCP
    if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("\n\033[31mSocket creation failed\033[0m\n");
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "\033[35m[LOG]\033[0m Socket created\n");

    // Attach serverSocket to the port 12000
    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("\n\033[31mSet socket options failed\033[0m\n");
        exit(EXIT_FAILURE);
    }
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("\n\033[31mSet socket options failed\033[0m\n");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET; // address family is IPv4
    address.sin_addr.s_addr = INADDR_ANY; // socket will be bound to all local interfaces
    address.sin_port = htons(SERVERPORT); // set port number
    if (bind(serverSocket, (struct sockaddr*)&address, addrlen) < 0) {
        perror("\n\033[31mBinding socket to port failed\033[0m\n");
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "\033[35m[LOG]\033[0m Socket attached to port\n");

    // Listen for connections
    int maxWaitingToConnect = 10;
    if (listen(serverSocket, maxWaitingToConnect) < 0) {
        perror("\n\033[31mListening for connection failed\033[0m\n");
        exit(EXIT_FAILURE);
    }

    // Create worker threads for handling clients
    pthread_t threads[THREAD_POOL_SIZE];
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        if (pthread_create(&threads[i], NULL, worker_thread, NULL) != 0) {
            perror("\n\033[31mFailed to create worker thread\033[0m\n");
            exit(EXIT_FAILURE);
        }
    }
    fprintf(stderr, "\033[35m[LOG]\033[0m Thread pool initialized\n");

    while (true) { // keep listening for new connections
        fprintf(stderr, "\033[35m[LOG]\033[0m Listening for connections\n");

        // Accept connections
        if ((perClientSocket = accept(serverSocket, (struct sockaddr*)&address, &addrlen)) < 0) {
            perror("\n\033[31mAccepting connection failed\033[0m\n");
            exit(EXIT_FAILURE);
        }
        
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(address.sin_addr), ip_str, INET_ADDRSTRLEN);
        int port = ntohs(address.sin_port);  // Convert back to host byte order
        fprintf(stderr, "\033[35m[LOG]\033[0m Accepted client connection from %s:%d\n", ip_str, port);

        // Add accepted client socket to the job queue for worker threads
        queue_push(&job_queue, perClientSocket);
    }

    return 0;
}
