CC = clang
CFLAGS = -Wall -lssl -lcrypto -I./Client -I./encryption
CLIENTFLAGS = -Wall -lpthread -lncurses -lssl -lcrypto -I./Client -I./encryption

CLIENT_SRC = ./Client/client.c ./encryption/encryption.c
CLIENT_HDR = ./Client/client.h ./encryption/encryption.h

SERVER_SRC = ./Server/server.c ./encryption/encryption.c
SERVER_HDR = ./Server/server.h ./encryption/encryption.h

all: bin_client bin_server

bin_client: $(CLIENT_SRC) $(CLIENT_HDR)
	$(CC) $(CLIENTFLAGS) $(CLIENT_SRC) -o client.out

bin_server: $(SERVER_SRC) $(SERVER_HDR)
	$(CC) $(CFLAGS) $(SERVER_SRC) -o server.out

clean:
	rm -rf client.out server.out downloads/
