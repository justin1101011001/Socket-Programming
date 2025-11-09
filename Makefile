CC = clang
CFLAGS = -Wall
CLIENTFLAGS = -Wall -lpthread -lncurses

CLIENT_SRC = ./Client/client.c
CLIENT_HDR = ./Client/client.h

SERVER_SRC = ./Server/server.c
SERVER_HDR = ./Server/server.h

all: bin_client bin_server

bin_client: $(CLIENT_SRC) $(CLIENT_HDR)
	$(CC) $(CLIENTFLAGS) $(CLIENT_SRC) -o client.out

bin_server: $(SERVER_SRC) $(SERVER_HDR)
	$(CC) $(CFLAGS) $(SERVER_SRC) -o server.out

clean:
	rm -f client.out server.out
