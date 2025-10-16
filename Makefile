CC = clang
CFLAGS = -Wall

CLIENT_SRC = ./Client/client.c
SERVER_SRC = ./Server/server.c

all: bin_client bin_server

bin_client: $(CLIENT_SRC)
	$(CC) $(CFLAGS) $(CLIENT_SRC) -o client.out

bin_server: $(SERVER_SRC)
	$(CC) $(CFLAGS) $(SERVER_SRC) -o server.out

clean:
	rm -f client.out server.out
