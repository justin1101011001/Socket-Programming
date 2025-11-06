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
#define GREEN_TEXT   "\033[32m"
#define YELLOW_TEXT  "\033[33m"
#define BOLD_TEXT    "\033[1m"
#define RESET_TEXT   "\033[0m"

// Macro that wraps text in red formatting
#define RED(msg) RED_TEXT msg RESET_TEXT
#define GREEN(msg) GREEN_TEXT msg RESET_TEXT
#define YELLOW(msg) YELLOW_TEXT msg RESET_TEXT
#define BOLD(msg) BOLD_TEXT msg RESET_TEXT

static int connectToServer(int clientSocket);
static int setListeningSocket(int listeningSocket, int listeningPort);
static void sendMessage(int socket, char *buffer);
static void readMessage(int socket, char *buffer);
static int parseInput(char *token, char *buffer);
static int setListeingPort(int argc, const char **argv);

#endif /* client_h */
