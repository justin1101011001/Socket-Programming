//
//  server.h
//  Server
//
//  Created by Justin Liao on 2025.10.28.
//

#ifndef server_h
#define server_h

#define BUFFERSIZE 1024
#define JOB_QUEUE_SIZE 16

// ANSI color codes
#define RED_TEXT     "\033[31m"
#define GREEN_TEXT   "\033[32m"
#define MAGENTA_TEXT "\033[35m"
#define CYAN_TEXT    "\033[36m"
#define RESET_TEXT   "\033[0m"

// Macro that wraps text in red formatting
#define RED(msg) RED_TEXT msg RESET_TEXT
#define GREEN(msg) GREEN_TEXT msg RESET_TEXT
#define MAGENTA(msg) MAGENTA_TEXT msg RESET_TEXT
#define CYAN(msg) CYAN_TEXT msg RESET_TEXT

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

void queue_init(JobQueue *q);
void queue_push(JobQueue *q, int sock);
int queue_pop(JobQueue *q);
static void handle_client(int perClientSocket);
void* worker_thread(void* arg);
int setSocket(int serverSocket);
void createThreads(void);

#endif /* server_h */
