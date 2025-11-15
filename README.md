# Compilation
To compile, run ``make`` in the folder where the ``Makefile`` is, this should create two executables ``client.out`` and ``server.out``.

# Usage
To start the server, run ``./server.out`` directly, and use ``exit`` to end execution. A list of registered users can be displayed using ``list``.

To run the client, use ``./client.out <port number>``. The ``<port number>`` should be an integer in the range [49152, 65535].
There are 8 available actions in the client program:
 1. Registration: Registers a new user with the server. Syntax: ``register <ID> <password>``
 2. Deregistration: Deregisters an existing user from the server. Syntax: ``deregister <ID> <password>``
 3. Login: Logs in to a user that is already registered. Syntax: ``login <ID> <password>``
 4. Logout: Logs out the currently logged in user. Syntax: ``logout``
 5. List Online Users: Lists out the users that are currently online. Syntax: ``list``
 6. Chat with Online User: Send and receive messages with another online user. Syntax: ``chat <Target ID>``
 7. Accept Chat Request: Accept chat request from another user and start a chat session. Syntax: ``accept`` (When prompted)
 8. Exit Client Program: Ends the client program. Syntax: ``exit``

You can also type ``help`` in the client program to view this list. 

# Additional Information
- Please only start inputting when you see the prompt ``>``. 
- Each command should be no more than 1,024 characters long.
- While in the chat session UI, the input field will scroll if the message is longer than the current window size, the message will still be sent in whole. The maximum length of one message should still be less than 1,024 characters long.
- A ``Data/`` folder will be created in the project root directory to store registered users across server sessions.
