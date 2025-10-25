# Compilation
To compile, run ``make`` in the folder where the ``Makefile`` is, this should create two executables ``client.out`` and ``server.out``.

# Usage
To start the server, run ``./server.out`` directly, and use ``^C`` to end execution.

To run the client, use ``./client.out <port number>``. The ``<port number>`` should be an integer in the range [49152, 65535].
There are 5 available actions in the client program:
 1. Registration: Registers a new user with the server. Syntax: ``register <ID> <password>``
 2. Login: Logs in to a user that is already registered. Syntax: ``login <ID> <password>``
 3. Logout: Logs out the currently logged in user. Syntax: ``logout``
 4. List Online Users: Lists out the users that are currently online. Syntax: ``list``
 5. Exit Client Program: Ends the client program. Syntax: ``exit``

You can also type ``help`` in the client program to view this list. 
Please only start inputting when you see the prompt ``>``. 
Should you accidentally make a typo when typing a command, summit the command directly(instead of using backspace to correct it) and retry. 
Each command should be no more than 1,024 characters long.

# Additional Information
N/A
