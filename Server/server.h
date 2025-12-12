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
#define KEYBYTES 512
#define KEY_LEN 32        // AES-256 -> 32 bytes
#define IV_LEN 12         // 96-bit
#define TAG_LEN 16        // 128-bit tag

// ANSI color codes
#define RED_TEXT     "\033[31m"
#define GREEN_TEXT   "\033[32m"
#define YELLOW_TEXT  "\033[33m"
#define MAGENTA_TEXT "\033[35m"
#define CYAN_TEXT    "\033[36m"
#define RESET_TEXT   "\033[0m"

// Macro that wraps text in red formatting
#define RED(msg) RED_TEXT msg RESET_TEXT
#define GREEN(msg) GREEN_TEXT msg RESET_TEXT
#define YELLOW(msg) YELLOW_TEXT msg RESET_TEXT
#define MAGENTA(msg) MAGENTA_TEXT msg RESET_TEXT
#define CYAN(msg) CYAN_TEXT msg RESET_TEXT

// User structure
typedef struct userClient {
    char ID[BUFFERSIZE];
    char password[BUFFERSIZE];
    struct sockaddr_in address;
    struct userClient *regNext;
    struct userClient *regPrev;
    struct userClient *logNext;
    struct userClient *logPrev;
} User;

// Job queue for client socket descriptors
typedef struct {
    int sockets[JOB_QUEUE_SIZE];
    int front, rear, count;
    pthread_mutex_t mutex;
    pthread_cond_t cond_nonempty;
    pthread_cond_t cond_nonfull;
} JobQueue;

static void queue_init(JobQueue *q);
static void queue_push(JobQueue *q, int sock);
static int queue_pop(JobQueue *q);
static void handle_client(int perClientSocket);
static void *worker_thread(void* arg);
static int setSocket(int serverSocket);
static void createThreads(void);
static int sendMessage(int socket, char *buffer);
static int readMessage(int socket, char *buffer);
static void parseMessage(char *token, char (*input)[BUFFERSIZE]);
static int acceptConnection(int socket, int serverSocket);
static void removeFromList(bool mode, User **currentUserPtr);
static User *checkUserInList(bool mode, char *userID);
static User *insertUserToList(bool mode, char *userID, char *password, struct sockaddr_in *clientListenAddress, User **loginUser);
static void *consoleWatcher(void *arg);
static void cleanUp(void);
static void saveUsers(char *fileName);
static void readUsers(char *fileName);
static int directoryExists(const char *path);

#endif /* server_h */
