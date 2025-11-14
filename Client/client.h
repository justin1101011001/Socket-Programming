//
//  client.h
//  Client
//
//  Created by Justin Liao on 2025.10.28.
//

#ifndef client_h
#define client_h

// ANSI color codes
#define RED_TEXT     "\033[31m"
#define BRED_TEXT    "\033[41m"
#define GREEN_TEXT   "\033[32m"
#define YELLOW_TEXT  "\033[33m"
#define BLUE_TEXT    "\033[34m"
#define BBLUE_TEXT   "\033[44m"
#define BOLD_TEXT    "\033[1m"
#define RESET_TEXT   "\033[0m"

// Macro that wraps text in red formatting
#define RED(msg) RED_TEXT msg RESET_TEXT
#define BRED(msg) BRED_TEXT msg RESET_TEXT
#define GREEN(msg) GREEN_TEXT msg RESET_TEXT
#define YELLOW(msg) YELLOW_TEXT msg RESET_TEXT
#define BLUE(msg) BLUE_TEXT msg RESET_TEXT
#define BBLUE(msg) BBLUE_TEXT msg RESET_TEXT
#define BOLD(msg) BOLD_TEXT msg RESET_TEXT

#define BUFFERSIZE 1024

typedef struct windowPair {
    WINDOW *message;
    WINDOW *input;
    WINDOW *time;
} WindowPair;

static int connectToServer(int clientSocket);
static int setListeningSocket(int listeningSocket, int listeningPort);
static int sendMessage(int socket, char *buffer);
static void readMessage(int socket, char *buffer);
static int parseInput(char *token, char *buffer, char (*input)[BUFFERSIZE]);
static int setListeingPort(int argc, const char **argv);
static void oneToOneChat(void);
static void *recvMessage(void *arg);
static void *acceptDM(void *arg);

#endif /* client_h */
