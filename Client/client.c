#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <pthread.h>
#include <ncurses.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include "client.h"

#define SERVERPORT 12014
#define BUFFERSIZE 1024

static pthread_t messageReciever;
static pthread_t DMAcceptor;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t drawWindow = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t readyToAccept = PTHREAD_COND_INITIALIZER; // Used by acceptDM to indicate readiness to accept the next connection from a peer

bool acceptSignal = false; // DM request accpeted, used by acceptDM to indicate readiness to accept the next connection from a peer
bool DMOngoing = false; // Flag indicating if there's an ongoing DM session
bool pendingRequest = false; // Flag indicating if there's a pending DM request from a peer

char currentUserID[100] = "";
char currentPeerID[100] = "";
char lastMessageSentBy[100] = ""; // Who sent the last message? Used for message window drawing

int peerSocket; // Used for DM with a peer

int main(int argc, char const* argv[]) {
//MARK: - Socket Setup
    int listeningPort = setListeingPort(argc, argv); // Get listening port from arguments
    int listeningSocket = 0, clientSocket = 0;
    listeningSocket = setListeningSocket(listeningSocket, listeningPort); // Set listening socket

    char recvBuffer[BUFFERSIZE] = {0}; // buffer for messages from server
    char inputBuffer[BUFFERSIZE] = {0}; // buffer for user input
    bool loggedIn = false; // is the user currently logged in
    
    // Create thread to accept DM requests
    if (pthread_create(&DMAcceptor, NULL, acceptDM, &listeningSocket) != 0) {
        perror(RED("[ERROR]")" Failed to create DM acceptor thread\n");
        exit(EXIT_FAILURE);
    }
    
    while (true) {
        printf(BOLD("%s> "), currentUserID);
        fflush(stdout);
        fgets(inputBuffer, BUFFERSIZE, stdin); // read whole line of input
        inputBuffer[strcspn(inputBuffer, "\n")] = '\0'; // trim off the newline character at the end
        char *token; // Pointer to store each token
        token = strtok(inputBuffer, " "); // Get the first token of input
        if (token == NULL) { // Empty command, continue reading
            continue;
        }
       
//MARK: - Exit
        if (strcmp(token, "exit") == 0) { // exit and end the client process
            if (loggedIn) {
                strcpy(token, "logout");
                sendMessage(clientSocket, token);
                readMessage(clientSocket, recvBuffer);
                close(clientSocket);
                
                loggedIn = false;
                printf("%s", recvBuffer);
            }
            break;
            
//MARK: - Logout
        } else if (strcmp(token, "logout") == 0) { // logout put keeps the client process running
            if (!loggedIn) {
                printf("You are currently not logged in to any account.\n");
                continue;
            }
            
            sendMessage(clientSocket, token);
            readMessage(clientSocket, recvBuffer);
            close(clientSocket);
            currentUserID[0] = '\0';
            loggedIn = false;
            printf("%s", recvBuffer);
            
//MARK: - Register
        } else if (strcmp(token, "register") == 0) {
            char sendBuffer[BUFFERSIZE] = "";
            int parameterIndex = parseInput(token, sendBuffer, NULL);
            
            if (parameterIndex == 3) { // correct number of parameters
                if (loggedIn) {
                    printf("You are already logged in to an account, please logout before creating a new account.\n");
                    continue;
                }
                
                clientSocket = connectToServer(clientSocket);
                if (clientSocket < 0) continue;
                sendMessage(clientSocket, sendBuffer);
                readMessage(clientSocket, recvBuffer);
                close(clientSocket);
                printf("%s", recvBuffer);
            } else {
                printf("Invalid parameters.\nUsage: register <ID> <password>\n");
            }
            
//MARK: - Deregister
        } else if (strcmp(token, "deregister") == 0) {
            if (!loggedIn) { // Can't deregister without logging in
                printf("Please log in first to start the deregistration process.\n");
                continue;
            }
            
            char sendBuffer[BUFFERSIZE] = "";
            int parameterIndex = parseInput(token, sendBuffer, NULL);
            
            if (parameterIndex == 2) {
                sendMessage(clientSocket, sendBuffer); // Send deregistration request
                readMessage(clientSocket, recvBuffer); // Read comfirmation message
                printf("%s", recvBuffer);
                
                if (strncmp(recvBuffer, "You", 3) == 0) { // Password check passed
                    // User input to confirm deregistration
                    printf(BOLD("%s> "), currentUserID);
                    fgets(inputBuffer, BUFFERSIZE, stdin); // read whole line of input
                    inputBuffer[strcspn(inputBuffer, "\n")] = '\0'; // trim off the newline character at the end
                    sendMessage(clientSocket, inputBuffer); // Send comfirmation
                    readMessage(clientSocket, recvBuffer); // Server response
                    
                    if (strncmp(recvBuffer, "Success", 7) == 0) { // Deregistered successsfully
                        close(clientSocket);
                        currentUserID[0] = '\0';
                        loggedIn = false;
                    }

                    printf("%s", recvBuffer);
                }
            } else {
                printf("Invalid parameters.\nUsage: deregister <password>\n");
            }
            
//MARK: - Login
        } else if (strcmp(token, "login") == 0) {
            char sendBuffer[BUFFERSIZE] = "";
            char inputTokens[3][BUFFERSIZE] = {0}; // 1 ID, 2 password
            int parameterIndex = parseInput(token, sendBuffer, inputTokens);
            
            if (parameterIndex == 3) { // correct number of parameters
                if (loggedIn) {
                    printf("You are already logged in to an account, please logout before logging in to another account.\n");
                    continue;
                }
                
                clientSocket = connectToServer(clientSocket);
                if (clientSocket < 0) continue;
                sendMessage(clientSocket, sendBuffer);
                readMessage(clientSocket, recvBuffer);
                
                if (strncmp(recvBuffer, "OK.", 3) == 0) { // if successfully logged in
                    int32_t formatted = htons(listeningPort); // Send listening port
                    send(clientSocket, &formatted, sizeof(int32_t), 0);
                    loggedIn = true;
                    
                    strcpy(currentUserID, inputTokens[1]); // Add logged in user name to prompt
                    readMessage(clientSocket, recvBuffer);
                }
                
                printf("%s", recvBuffer);
            } else {
                printf("Invalid parameters.\nUsage: login <ID> <password>\n");
            }
            
//MARK: - List
        } else if (strcmp(token, "list") == 0) {
            if (!loggedIn) {
                printf("You are currently not logged in, plaese login to use this feature.\n");
                continue;
            }
            
            sendMessage(clientSocket, token);
            readMessage(clientSocket, recvBuffer);
            printf(GREEN("Online Users\n====================\n"));
            while (strcmp(recvBuffer, "END OF USER LIST") != 0) {
                printf(GREEN("%s\n"), recvBuffer);
                readMessage(clientSocket, recvBuffer);
            }
            
//MARK: - DM
        } else if (strcmp(token, "chat") == 0) {
            char sendBuffer[BUFFERSIZE] = "";
            char inputTokens[2][BUFFERSIZE] = {0}; // 1 peerID
            int parameterIndex = parseInput(token, sendBuffer, inputTokens);
            
            if (parameterIndex == 2) { // correct number of parameters
                if (!loggedIn) {
                    printf("You are currently not logged in, plaese login to use this feature.\n");
                    continue;
                }
                if (strcmp(inputTokens[1], currentUserID) == 0) { // Don't allow messaging oneself
                    printf("??? Make some friends???\n");
                    continue;
                }
                if (DMOngoing) {
                    printf(RED("Cannot have more than one ongoing chat at once.\n"));
                    continue;
                }
                
                // Get peer address from server
                sendMessage(clientSocket, sendBuffer);
                readMessage(clientSocket, recvBuffer);
                if (strncmp(recvBuffer, "Peer", 4) == 0) { // Peer offline
                    printf("%s", recvBuffer);
                    continue;
                }
                
                struct sockaddr_in peerAddress;
                socklen_t addrlen = sizeof(peerAddress); // length of address
                peerAddress.sin_family = AF_INET; // address family is IPv4
                read(clientSocket, &(peerAddress.sin_addr.s_addr), sizeof(in_addr_t));
                read(clientSocket, &(peerAddress.sin_port), sizeof(in_port_t));

                // Connect to peer
                if ((peerSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
                    perror(RED("[ERROR]")" Socket creation failed\n");
                    exit(EXIT_FAILURE);
                }
                if (connect(peerSocket, (struct sockaddr*)&peerAddress, addrlen) < 0) {
                    printf(RED("Peer offline :(\n"));
                    peerSocket = -1;
                    continue;
                }
                
                pthread_mutex_lock(&mutex);
                DMOngoing = true;
                pthread_mutex_unlock(&mutex);
                
                // Wait for peer response
                char response[3];
                sendMessage(peerSocket, currentUserID); // Send messaging request
                printf(YELLOW("Waiting for peer to repond, please wait(10s)...")"\n");
                readMessage(peerSocket, response);
                
                if (strcmp(response, "no") == 0) { // Request timed out
                    printf(YELLOW("Peer did not accept DM request :(\n"));
                    DMOngoing = false;
                    pthread_mutex_unlock(&mutex);
                    continue;
                } else if (strcmp(response, "nob") == 0) { // Peer in another chat session already
                    printf(YELLOW("Peer busy, please try again later.\n"));
                    DMOngoing = false;
                    pthread_mutex_unlock(&mutex);
                    continue;
                }
                
                // Start chat session
                printf(YELLOW("Entering chat...\n"));
                strcpy(currentPeerID, inputTokens[1]);
                oneToOneChat();
                printf(YELLOW("...chat with %s ended\n"), currentPeerID);
                close(peerSocket);
                peerSocket = -1;
                currentPeerID[0] = '\0';
                
                pthread_mutex_lock(&mutex);
                DMOngoing = false;
                pthread_mutex_unlock(&mutex);
                
            } else {
                printf("Invalid parameters.\nUsage: chat <ID>\n");
            }
            
//MARK: - Accept DM
        } else if (strcmp(token, "accept") == 0){
            if (!loggedIn) {
                printf("You are currently not logged in, plaese login to use this feature.\n");
                continue;
            }
            if (!pendingRequest) {
                printf(YELLOW("No incoming message requests now.\n"));
                continue;
            }
            if (DMOngoing) {
                printf(RED("Cannot have more than one ongoing chat at once.\n"));
                continue;
            }
            
            // Notify acceptDM thread ready to accpet next incoming request
            pthread_mutex_lock(&mutex);
            DMOngoing = true;
            acceptSignal = true;
            pthread_cond_signal(&readyToAccept);
            pthread_mutex_unlock(&mutex);
            
            // Accept DM request
            sendMessage(peerSocket, "yes");
            
            // Start chat session
            printf(YELLOW("Entering chat...\n"));
            oneToOneChat();
            printf(YELLOW("...chat with %s ended\n"), currentPeerID);
            close(peerSocket);
            peerSocket = -1;
            currentPeerID[0] = '\0';
            
            pthread_mutex_lock(&mutex);
            DMOngoing = false;
            pthread_mutex_unlock(&mutex);
            
//MARK: - Help
        } else if (strcmp(token, "help") == 0) {
            printf(YELLOW("%-25s")": %-25s\n", "Registration", "register <ID> <password>");
            printf(YELLOW("%-25s")": %-25s\n", "Deregistration", "deregister <ID> <password>");
            printf(YELLOW("%-25s")": %-25s\n", "Login", "login <ID> <password>");
            printf(YELLOW("%-25s")": %-25s\n", "Logout", "logout");
            printf(YELLOW("%-25s")": %-25s\n", "List Online Users", "list");
            printf(YELLOW("%-25s")": %-25s\n", "Chat with user", "chat <ID>");
            printf(YELLOW("%-25s")": %-25s\n", "Accept chat request", "chat <ID>");
            printf(YELLOW("%-25s")": %-25s\n", "Exit Client Program", "exit");
        } else {
            printf("Unknown command, type \"help\" for usage.\n");
        }
    }
    
    pthread_cancel(DMAcceptor);
    pthread_join(DMAcceptor, NULL);
    
    pthread_mutex_destroy(&mutex);
    pthread_mutex_destroy(&drawWindow);
    pthread_cond_destroy(&readyToAccept);
    
    return 0;
}

static void *acceptDM(void *arg) { // Thread function to constantly listen for peer chat requests
    int tmp, listeningSocket = *(int *)arg;
    struct sockaddr_in address; // IP and port number to bind the socket to
    socklen_t addrlen = sizeof(address); // length of address
    
    while (true) {
        // Accept new connection
        if ((tmp = accept(listeningSocket, (struct sockaddr*)&address, &addrlen)) < 0) {
            fprintf(stderr, RED("[ERROR]")" Accepting connection failed\n");
            continue;
        }
        
        // Reject request if a chat session is already in progress
        pthread_mutex_lock(&mutex);
        if (DMOngoing) {
            readMessage(tmp, NULL);
            sendMessage(tmp, "nob");
            shutdown(tmp, SHUT_WR);  // Finish sending, tell peer “no more data”
            close(tmp);
            pthread_mutex_unlock(&mutex);
            continue;
        }
        pthread_mutex_unlock(&mutex);

        // Read peer ID, ask user to accept request. Request times out after 30 seconds if user doesn't accept
        peerSocket = tmp;
        readMessage(peerSocket, currentPeerID);
        printf("\n"YELLOW("[INCOMING]")BLUE(" %s")" wants to chat, accept? [accept](10s)\n", currentPeerID);
        printf(BOLD("%s> "), currentUserID);
        fflush(stdout);
        
        // Wait 10 seconds or request accepted
        pthread_mutex_lock(&mutex);
        pendingRequest = true;
        
        // Compute wake-up time (30 seconds from now)
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 10;
        
        // Wait for accept or timeout
        while (!acceptSignal) {
            int ret = pthread_cond_timedwait(&readyToAccept, &mutex, &ts);
            if (ret == ETIMEDOUT) {
                sendMessage(peerSocket, "no");
                shutdown(peerSocket, SHUT_WR);
                close(peerSocket);
                currentPeerID[0] = '\0';
                peerSocket = -1;
                break;
            }
        }
        
        acceptSignal = false;
        pendingRequest = false;
        pthread_mutex_unlock(&mutex);
        
        pthread_testcancel();
    }
    
    return NULL;
}

char prevTimestamp[17] ; // Store previous time stamp
static void oneToOneChat(void) {
    // UI setup
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    start_color(); // Enable color functionality
    use_default_colors(); // Optional: allow transparency with terminal default background
    
    init_pair(1, COLOR_RED, -1); // Red text on default background
    init_pair(2, COLOR_BLUE, -1); // Blue text on default background
    init_pair(3, COLOR_YELLOW, -1); // Yellow text on default background
    
    int rows, cols;
    getmaxyx(stdscr, rows, cols);
    
    WINDOW *messageWindow = newwin(rows - 2, cols - 17, 0, 0); // Rows 0 ~ (rows - 3), Columns 0 ~ (cols - 21)
    WINDOW *inputWindow = newwin(1, cols, rows - 1, 0);
    WINDOW *statusWindow = newwin(1, cols, rows - 2, 0);
    WINDOW *timeWindow = newwin(rows - 2, 17, 0, cols - 17);
    wbkgd(statusWindow, A_REVERSE | COLOR_PAIR(3));
    wbkgd(timeWindow, A_DIM);
    scrollok(messageWindow, TRUE);
    idlok(messageWindow, TRUE);
    scrollok(timeWindow, TRUE);
    idlok(timeWindow, TRUE);
    scrollok(inputWindow, TRUE);
    idlok(inputWindow, TRUE);
    
    WindowPair threadData;
    threadData.message = messageWindow;
    threadData.input = inputWindow;
    threadData.time = timeWindow;
    // Create message reciever thread for chat
    if (pthread_create(&messageReciever, NULL, recvMessage, &threadData) != 0) {
        perror(RED("[ERROR]")" Failed to create message reciever thread\n");
        endwin();
        exit(EXIT_FAILURE);
    }
    
    char inputBuffer[BUFFERSIZE] = ""; // buffer for user input
    int pos = 0;
    int currentUserIDLength = (int)(strlen(currentUserID));
    int inputCharacter;
    
    // Draw message area
    pthread_mutex_lock(&drawWindow);
    werase(messageWindow);
    wprintw(messageWindow, "");
    wrefresh(messageWindow);
    pthread_mutex_unlock(&drawWindow);
    
    // Draw timestamp area
    pthread_mutex_lock(&drawWindow);
    werase(timeWindow);
    wprintw(timeWindow, "");
    wrefresh(timeWindow);
    pthread_mutex_unlock(&drawWindow);
    
    // Draw status bar
    pthread_mutex_lock(&drawWindow);
    werase(statusWindow);
    mvwprintw(statusWindow, 0, 0, " Chatting with %s | Press ESC to leave ", currentPeerID);
    wrefresh(statusWindow);
    pthread_mutex_unlock(&drawWindow);

    // Draw input field
    pthread_mutex_lock(&drawWindow);
    werase(inputWindow);
    wattron(inputWindow, COLOR_PAIR(1));
    mvwprintw(inputWindow, 0, 0, "%s> %s", currentUserID, inputBuffer);
    wattroff(inputWindow, COLOR_PAIR(1));
    curs_set(1); // Show cursor
    wmove(inputWindow, 0, pos + 2 + currentUserIDLength); // Move cursor to inputWindow
    wrefresh(inputWindow);
    pthread_mutex_unlock(&drawWindow);
    
    char timestamp[17];
    time_t now = time(NULL) - 60; // -60 to trigger the first message
    struct tm *t = localtime(&now);
    strftime(prevTimestamp, sizeof(prevTimestamp), "%a %b %d %H:%M", t);
    int curY, curX; // Record cursor position, used for printing timestamp at the correct position
    
    // Keep reading user input and send them
    while (true) {
        inputCharacter = wgetch(inputWindow);
        if (inputCharacter == 27) { // ESC key, end chat session
            break;
        } else if (peerSocket < 0) { // Peer has left
            continue;
        } else if (inputCharacter == '\n') { // Input with \n as ending
            if (pos > 0) { // User has input something
                inputBuffer[pos] = '\0';
                
                // Display & send message
                sendMessage(peerSocket, inputBuffer);
                
                pthread_mutex_lock(&drawWindow);
                // Print timestamp
                now = time(NULL);
                t = localtime(&now);
                strftime(timestamp, sizeof(timestamp), "%a %b %d %H:%M", t);
                if (strcmp(prevTimestamp, timestamp) != 0) {
                    getyx(messageWindow, curY, curX); // Get cursor position after last message is printed
                    int startCol = 17 - (int)strlen(timestamp);
                    mvwprintw(timeWindow, curY, startCol, "%s", timestamp);
                    wrefresh(timeWindow);
                    
                    strcpy(prevTimestamp, timestamp);
                }
                
                // Print sender
                wattron(messageWindow, COLOR_PAIR(1));
                if (strcmp(lastMessageSentBy, currentUserID) != 0) { // Last message not sent by current user, print sender
                    wprintw(messageWindow, "%s:\n", currentUserID);
                    strcpy(lastMessageSentBy, currentUserID);
                }
                
                // Print message
                wprintw(messageWindow, " > %s\n", inputBuffer);
                wattroff(messageWindow, COLOR_PAIR(1));
                wrefresh(messageWindow);
                pthread_mutex_unlock(&drawWindow);
                
                pos = 0;
                memset(inputBuffer, 0, sizeof(inputBuffer));
            }
        } else if (inputCharacter == KEY_BACKSPACE || inputCharacter == 127) { // Backspace
            if (pos > 0) {
                inputBuffer[--pos] = '\0';
            }
        } else if (isprint(inputCharacter) && pos < BUFFERSIZE - 1) {
            inputBuffer[pos++] = inputCharacter;
        }
        
        // Draw Status bar
        pthread_mutex_lock(&drawWindow);
        werase(statusWindow);
        mvwprintw(statusWindow, 0, 0, " Chatting with %s | Press ESC to leave ", currentPeerID);
        wrefresh(statusWindow);
        pthread_mutex_unlock(&drawWindow);

        // Draw input field
        pthread_mutex_lock(&drawWindow);
        werase(inputWindow);
        wattron(inputWindow, COLOR_PAIR(1));
        mvwprintw(inputWindow, 0, 0, "%s> %s", currentUserID, inputBuffer);
        wattroff(inputWindow, COLOR_PAIR(1));
        wrefresh(inputWindow);
        pthread_mutex_unlock(&drawWindow);
    }
    
    if (peerSocket > 0) { // Initiate termination from this side
        sendMessage(peerSocket, "CLOSEDM");
    }
    
    // Cancel the message recieving thread
    pthread_cancel(messageReciever);
    pthread_join(messageReciever, NULL);
    endwin();
    return;
}

static void *recvMessage(void *arg) {
    WindowPair threadData = *(WindowPair *)arg;
    char recvBuffer[BUFFERSIZE] = ""; // buffer for messages from peer
    
    char timestamp[17];
    time_t now = time(NULL) - 60; // -60 to trigger the first message
    struct tm *t = localtime(&now);
    strftime(prevTimestamp, sizeof(prevTimestamp), "%a %b %d %H:%M", t);
    int curY, curX; // Record cursor position, used for printing timestamp at the correct position
    
    while (true) {
        readMessage(peerSocket, recvBuffer);
        
        if (strcmp(recvBuffer, "CLOSEDM") == 0) {
            close(peerSocket);
            peerSocket = -1;
            
            pthread_mutex_lock(&drawWindow);
            wattron(threadData.message, COLOR_PAIR(3));
            wprintw(threadData.message, "Peer left the chat. (Hit ESC to continue)\n");
            wattroff(threadData.message, COLOR_PAIR(3));
            wrefresh(threadData.message);
            wrefresh(threadData.input);
            pthread_mutex_unlock(&drawWindow);
            break;
        } else {
            pthread_mutex_lock(&drawWindow);
            // Print timestamp
            now = time(NULL);
            t = localtime(&now);
            strftime(timestamp, sizeof(timestamp), "%a %b %d %H:%M", t);
            if (strcmp(prevTimestamp, timestamp) != 0) {
                getyx(threadData.message, curY, curX); // Get cursor position after message is printed
                int startCol = 17 - (int)strlen(timestamp);
                mvwprintw(threadData.time, curY, startCol, "%s", timestamp);
                wrefresh(threadData.time);
                
                strcpy(prevTimestamp, timestamp);
            }
            
            // Print sender
            wattron(threadData.message, COLOR_PAIR(2));
            if (strcmp(lastMessageSentBy, currentPeerID) != 0) { // Last message not sent by peer, print sender
                wprintw(threadData.message, "%s:\n", currentPeerID);
                strcpy(lastMessageSentBy, currentPeerID);
            }
            
            // Print message
            wprintw(threadData.message, " > %s\n", recvBuffer);
            wattroff(threadData.message, COLOR_PAIR(2));
            wrefresh(threadData.message);
            wrefresh(threadData.input);
            pthread_mutex_unlock(&drawWindow);
        }
        
        pthread_testcancel();
    }
    return NULL;
}

//MARK: - Helper Functions
static int connectToServer(int clientSocket) {
    struct sockaddr_in serverAddress; // IP and port number to bind the socket to
    socklen_t addrlen = sizeof(serverAddress); // length of address
    
    // Create socket file descriptor
    if ((clientSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror(RED("Socket creation failed\n"));
        exit(EXIT_FAILURE);
    }
    
    serverAddress.sin_family = AF_INET; // address family is IPv4
    serverAddress.sin_port = htons(SERVERPORT); // set port number
    
    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &serverAddress.sin_addr) <= 0) {
        perror(RED("Invalid address/ Address not supported\n"));
        exit(EXIT_FAILURE);
    }
    
    // Connect to server
    if (connect(clientSocket, (struct sockaddr*)&serverAddress, addrlen) < 0) {
        perror(RED("Connection to server failed\n"));
        //exit(EXIT_FAILURE);
        clientSocket = -1;
    }
    
    return clientSocket;
}

static int setListeningSocket(int listeningSocket, int listeningPort) {
    struct sockaddr_in address; // IP and port number to bind the socket to
    socklen_t addrlen = sizeof(address); // length of address
    
    // Create socket file descriptor, use IPv4 and TCP
    if ((listeningSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror(RED("Socket creation failed\n"));
        exit(EXIT_FAILURE);
    }
    // Attach serverSocket to the port 12000
    int opt = 1;
    if (setsockopt(listeningSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror(RED("Set socket options failed\n"));
        exit(EXIT_FAILURE);
    }
    if (setsockopt(listeningSocket, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt))) {
        perror(RED("Set socket options failed\n"));
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET; // address family is IPv4
    address.sin_addr.s_addr = INADDR_ANY; // socket will be bound to all local interfaces
    address.sin_port = htons(listeningPort); // set port number
    if (bind(listeningSocket, (struct sockaddr*)&address, addrlen) < 0) {
        perror(RED("Binding socket to port failed\n"));
        exit(EXIT_FAILURE);
    }
    
    // Listen for connections
    int maxWaitingToConnect = 0;
    if (listen(listeningSocket, maxWaitingToConnect) < 0) {
        perror(RED("[ERROR]")" Listening for connection failed\n");
        exit(EXIT_FAILURE);
    }
    
    return listeningSocket;
}

static int sendMessage(int socket, char *buffer) {
    int32_t messageLength = htonl(strlen(buffer) + 1);
    if (send(socket, &messageLength, sizeof(messageLength), 0) < 0) {
        return -1;
    }
    send(socket, buffer, strlen(buffer) + 1, 0);
    return 0;
}

static void readMessage(int socket, char *buffer) {
    int32_t messageLength;
    read(socket, &messageLength, sizeof(messageLength));
    read(socket, buffer, ntohl(messageLength));
    return;
}

static int parseInput(char *token, char *buffer, char (*input)[BUFFERSIZE]){
    int parameterIndex = 0;
    while (token != NULL) {
        if (parameterIndex >= 4) {
            break;
        }
        if (input != NULL) {
            strcpy(input[parameterIndex], token);
        }
        strcat(buffer, token);
        strcat(buffer, " ");
        token = strtok(NULL, " ");
        parameterIndex++;
    } // rebuild user input
    return parameterIndex;
}

static int setListeingPort(int argc, const char **argv) {
    if (argc != 2) {
        printf(RED("Usage: ./client.out <Listening port number>\n"));
        exit(-1);
    }
    
    int listeningPort = atoi(argv[1]); // socket fd
    if (listeningPort < 49152 || listeningPort > 65535) {
        printf(RED("Invalid port number, please choose in the range of [49152, 65535]\n"));
        exit(-1);
    }
    return listeningPort;
}
