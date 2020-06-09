import socket
import select
from Asymmetric_rsa import asymmetric
from Symmetric import symmetric
from DataBase import Users

class server:
    def __init__(self):
        self.table = Users()
        self.HEADER_LENGTH = 10
        self.IP = "0.0.0.0"
        self.PORT = 9999
        self.sym = symmetric()
        self.rsa = asymmetric()
        self.private_key, self.public_key = self.rsa.generating_keys()
        self.rsa.storing_keys(self.private_key, self.public_key)
        self.private_key, self.public_key = self.rsa.Reading_keys(self.private_key, self.public_key)
        # Create a socket
        # socket.AF_INET - address family, IPv4, some otehr possible are AF_INET6, AF_BLUETOOTH, AF_UNIX
        # socket.SOCK_STREAM - TCP, conection-based, socket.SOCK_DGRAM - UDP, connectionless, datagrams, socket.SOCK_RAW - raw IP packets
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # SO_ - socket option
        # SOL_ - socket option level
        # Sets REUSEADDR (as a socket option) to 1 on socket
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.connect()
        # List of sockets for select.select()
        self.sockets_list = [self.server_socket]

        # List of connected clients - socket as a key, user header and name as data
        self.clients = {}
        print(f'Listening for connections on {self.IP}:{self.PORT}...')

    def connect(self):
        # Bind, so server informs operating system that it's going to use given IP and port
        # For a server using 0.0.0.0 means to listen on all available interfaces, useful to connect locally to 127.0.0.1 and remotely to LAN interface IP
        self.server_socket.bind((self.IP, self.PORT))
        # This makes server listen to new connections
        self.server_socket.listen()

    def handle_socket_exceptions(self):
        for notified_socket in self.exception_sockets:
            # Remove from list for socket.socket()
            self.sockets_list.remove(notified_socket)
            # Remove from our list of users
            del self.clients[notified_socket]

    def recieve_symmetric_keys(self, client_socket, user_header, user_name, public_key1):
        try:
            # Receive our "header" containing message length, it's size is defined and constant
            key1 = client_socket.recv(self.HEADER_LENGTH)
            iv1 = client_socket.recv(self.HEADER_LENGTH)
            # If we received no data, client gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
            if not len(key1):
                return False
            if not len(iv1):
                return False
            len_key = int(key1.decode('latin-1').strip())
            len_iv = int(key1.decode('latin-1').strip())
            key = client_socket.recv(len_key)
            iv = client_socket.recv(len_iv)
            key = self.rsa.decryption(self.private_key, key)
            iv = self.rsa.decryption(self.private_key, iv)
            # Convert header to int value
            # key_length = int(key_header.decode('latin-1').strip())
            # iv_length = int(iv_header)
            # Return an object of message header and message data
            # return {'header': user_header, 'data': user_name, 'public_key': public_key1, 'key_header': key_header, 'key': client_socket.recv(key_length), 'iv_header': iv_header, 'iv':client_socket.recv(iv_length)}
            return {'header': user_header, 'data': user_name, 'public_key': public_key1, 'key': key, 'iv': iv
                , 'connected': False, 'userid': ""}
        except:
            # If we are here, client closed connection violently, for example by pressing ctrl+c on his script
            # or just lost his connection
            # socket.close() also invokes socket.shutdown(socket.SHUT_RDWR) what sends information about closing the socket (shutdown read/write)
            # and that's also a cause when we receive an empty message
            return False

    def receive_client_file(self, client_socket):
        try:

            # Receive our "header" containing message length, it's size is defined and constant
            message_header = client_socket.recv(self.HEADER_LENGTH)

            # If we received no data, client gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
            if not len(message_header):
                return False

            # Convert header to int value
            message_length = int(message_header.decode('latin-1').strip())

            # Return an object of message header and message data
            return message_header, client_socket.recv(message_length), self.rsa.read_public_key_server(client_socket.recv(1024))
        except:

            # If we are here, client closed connection violently, for example by pressing ctrl+c on his script
            # or just lost his connection
            # socket.close() also invokes socket.shutdown(socket.SHUT_RDWR) what sends information about closing the socket (shutdown read/write)
            # and that's also a cause when we receive an empty message
            return False

    def recieve_file_msg(self, client_socket):
        try:
            # Receive our "header" containing message length, it's size is defined and constant
            message_header = client_socket.recv(self.HEADER_LENGTH)
            # If we received no data, client gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
            if len(message_header) == 0:
                return False
            # Convert header to int value
            message_length = int(message_header.decode('latin-1').strip())
            data_enc = client_socket.recv(message_length)
            # Return an object of message header and message data
            # Convert header to int value
            message_header2 = client_socket.recv(self.HEADER_LENGTH)
            message_length2 = int(message_header2.decode('latin-1').strip())
            file_name = client_socket.recv(message_length2)
            message_header3 = client_socket.recv(self.HEADER_LENGTH)
            message_length3 = int(message_header3.decode('latin-1').strip())
            send_to = client_socket.recv(message_length3)
            # Return an object of message header and message data
            return {'header': message_header, 'data': data_enc, 'file_name': file_name, 'send': send_to}
        except Exception as e:
            print("Exception made in 'recieve_file_msg' -> ", e)


    def client_command(self, client_socket):
        try:
            command_header = client_socket.recv(self.HEADER_LENGTH)
            # If we received no data, client gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
            if len(command_header) == 0:
                print('Closed connection from: {}'.format(self.clients[client_socket]['data'].decode('latin-1')))
                # Remove from list for socket.socket()
                self.sockets_list.remove(client_socket)
                # Remove from our list of users
                del self.clients[client_socket]
                return False
            # Convert header to int value
            command_length = int(command_header.decode('latin-1').strip())
            command = client_socket.recv(command_length)
            command = self.rsa.decryption(self.private_key, command)
            command = command.decode('latin-1')
            print(command)
            if command == "new file":
                self.handle_new_file(client_socket)
            if command == "login":
                self.handle_login(client_socket)
            if command == "register":
                self.handle_register(client_socket)
            if command == "list":
                self.send_list(client_socket)
            if command == "log out":
                self.log_out_client(client_socket)
        except:
            return False

    def log_out_client(self, client_socket):
        for client_socket1 in self.clients:
            if client_socket1 == client_socket:
                print(str(self.clients[client_socket1]['data'])+" log outbfhrhrjhyjtjh")
                self.clients[client_socket1]['connected'] = False
                self.clients[client_socket1]['data'] = "None"
                self.clients[client_socket1]['userid'] = ""

    def legal_connected(self, username):
        for client_socket1 in self.clients:
            user = self.clients[client_socket1]
            if user['data'].decode('latin-1') == username and user['connected']:
                return False
        return True

    def send_list(self, client_socket):
        list_connected = []
        print(self.clients)
        for client_socket1 in self.clients:
            user1 = self.clients[client_socket1]
            if client_socket1 != client_socket and user1['connected']:
                list_connected.append(user1['data'].decode('latin-1'))
        string = "*".join(list_connected)
        print(string)
        string = string.encode("latin-1")
        string_header = f"{len(string):<{self.HEADER_LENGTH}}".encode('latin-1')
        for client_socket1 in self.clients:
            # But don't sent it to sender
            if client_socket1 == client_socket:
                client_socket1.send(string_header + string)
                break

    def receive_data_login_register(self, client_socket):
        id_header = client_socket.recv(self.HEADER_LENGTH)
        if len(id_header) == 0:
            # Remove from our list of users
            self.sockets_list.remove(client_socket)
            del self.clients[client_socket]
            return False
        # If we received no data, client gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
        # Convert header to int value
        id_length = int(id_header.decode('latin-1').strip())
        userid = client_socket.recv(id_length)
        userid = self.rsa.decryption(self.private_key, userid)
        userid = userid.decode('latin-1')
        # Return an object of message header and message data
        # Convert header to int value

        name_header = client_socket.recv(self.HEADER_LENGTH)
        # If we received no data, client gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
        # Convert header to int value
        if not len(name_header):
            self.sockets_list.remove(client_socket)
            # Remove from our list of users
            del self.clients[client_socket]
            return False
        name_length = int(name_header.decode('latin-1').strip())
        username = client_socket.recv(name_length)
        username = self.rsa.decryption(self.private_key, username)
        username = username.decode('latin-1')

        pass_header = client_socket.recv(self.HEADER_LENGTH)
        # If we received no data, client gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
        # Convert header to int value
        if not len(name_header):
            # Remove from our list of users
            self.sockets_list.remove(client_socket)
            del self.clients[client_socket]
            return False
        pass_length = int(pass_header.decode('latin-1').strip())
        password = client_socket.recv(pass_length)
        password = self.rsa.decryption(self.private_key, password)
        password = password.decode('latin-1')
        return userid, username, password

    def handle_register(self, client_socket):
        user_id, user_name, user_password = self.receive_data_login_register(client_socket)
        if self.table.sign_up(user_id, user_name, user_password):
            answer = "Yes".encode("latin-1")
            answer_header = f"{len(answer):<{self.HEADER_LENGTH}}".encode('latin-1')
            for client_socket1 in self.clients:
                # But don't sent it to sender
                if client_socket1 == client_socket:
                    client_socket1.send(answer_header + answer)
                    break
        else:
            answer = "No".encode("latin-1")
            answer_header = f"{len(answer):<{self.HEADER_LENGTH}}".encode('latin-1')
            for client_socket1 in self.clients:
                # But don't sent it to sender
                if client_socket1 == client_socket:
                    client_socket1.send(answer_header + answer)
                    break

    def handle_login(self, client_socket):
        user_id, user_name, user_password = self.receive_data_login_register(client_socket)
        if self.table.log_in(user_id, user_name, user_password) and not self.clients[client_socket]['connected'] and self.legal_connected(user_name):
            answer = "Yes".encode("latin-1")
            answer_header = f"{len(answer):<{self.HEADER_LENGTH}}".encode('latin-1')
            self.clients[client_socket]['connected'] = True
            self.clients[client_socket]['data'] = user_name.encode('latin-1')
            self.clients[client_socket]['userid'] = user_id
            self.clients[client_socket]['header'] = f"{len(user_name):<{self.HEADER_LENGTH}}".encode('latin-1')
            user = self.clients[client_socket]
            print(f'new connected {user["data"].decode("latin-1")}: {user["connected"]}')
            for client_socket1 in self.clients:
                # But don't sent it to sender
                if client_socket1 == client_socket:
                    client_socket1.send(answer_header + answer)
                    break
        else:
            answer = "No".encode("latin-1")
            answer_header = f"{len(answer):<{self.HEADER_LENGTH}}".encode('latin-1')
            user = self.clients[client_socket]
            print(f'no connected {user["data"].decode("latin-1")}: {user["connected"]}')
            for client_socket1 in self.clients:
                # But don't sent it to sender
                if client_socket1 == client_socket:
                    client_socket1.send(answer_header + answer)
                    break

    def handle_new_client_file(self, notified_socket):
        # Accept new connection
        # That gives us new socket - client socket, connected to this given client only, it's unique for that client
        # The other returned object is ip/port set
        client_socket, client_address = self.server_socket.accept()

        # Client should send his name right away, receive it
        user_header, user_name, public_key1 = self.receive_client_file(client_socket)

        client_socket.send(self.public_key)

        user = self.recieve_symmetric_keys(client_socket, user_header, user_name, public_key1)
        print(user)
        # If False - client disconnected before he sent his name
        if user is False:
            return user

        # Add accepted socket to select.select() list
        self.sockets_list.append(client_socket)

        # Also save username and username header
        self.clients[client_socket] = user

        print('Accepted new connection from {}:{}, username: {}, public_key:{}, key:{}'.format(*client_address,
                                                                                               user['data'].decode('latin-1'),
                                                                                               user['public_key'],
                                                                                               user['key']))
    def handle_new_file(self, notified_socket):
        # Receive message
        file_recieve = self.recieve_file_msg(notified_socket)
        # If False, client disconnected, cleanup
        if file_recieve is False:
            print('Closed connection from: {}'.format(self.clients[notified_socket]['data'].decode('latin-1')))
            # Remove from list for socket.socket()
            self.sockets_list.remove(notified_socket)
            # Remove from our list of users
            del self.clients[notified_socket]
            return file_recieve
        # Get user by notified socket, so we will know who sent the message
        user = self.clients[notified_socket]
        dec_message = self.sym.decrypt_file(user['key'], user['iv'], file_recieve["data"])
        send = self.rsa.decryption(self.private_key, file_recieve["send"]).decode()
        file_name = self.rsa.decryption(self.private_key, file_recieve["file_name"])
        #file_name = file_name.decode("latin-1")
        print(f'Received message from {user["data"].decode("latin-1")}: {file_name}')
        if send == "all":
            self.broadcast_file(notified_socket, user, dec_message, file_name)
            self.handle_socket_exceptions()
        else:
            self.send_file(notified_socket, user, dec_message, send, file_name)
            self.handle_socket_exceptions()

    def broadcast_file(self, notified_socket, user, dec_message, file_name):
        # Iterate over connected clients and broadcast message
        for client_socket in self.clients:
            # But don't sent it to sender
            user1 = self.clients[client_socket]
            if client_socket != notified_socket and user1['connected']:
                user1 = self.clients[client_socket]
                send_msg = self.sym.encrypt_file(user1['key'], user1['iv'], dec_message)
                msg_header = f"{len(send_msg):<{self.HEADER_LENGTH}}".encode('latin-1')
                #file_name = file_name.encode("latin-1")
                #file_name = self.rsa.encryption(user1['public_key'], file_name)
                msg_header2 = f"{len(file_name):<{self.HEADER_LENGTH}}".encode('latin-1')
                # Send user and message (both with their headers)
                # We are reusing here message header sent by sender, and saved username header send by user when he connected
                client_socket.send(user['header'] + user['data'] + msg_header + send_msg + msg_header2 + file_name)

    def send_file(self, notified_socket, user, dec_message, send, file_name):
        for client_socket in self.clients:
            # But don't sent it to sender/
            user1 = self.clients[client_socket]
            if client_socket != notified_socket and user1['data'].decode('latin-1') == send and user1['connected']:
                send_msg = self.sym.encrypt_file(user1['key'], user1['iv'], dec_message)
                msg_header = f"{len(send_msg):<{self.HEADER_LENGTH}}".encode('latin-1')
                #file_name = self.rsa.encryption(user1['public_key'], file_name)
                msg_header2 = f"{len(file_name):<{self.HEADER_LENGTH}}".encode('latin-1')
                #file_name = self.rsa.encryption(user1['public_key'], file_name)
                # Send user and message (both with their headers)
                # We are reusing here message header sent by sender, and saved username header send by user when he connected
                client_socket.send(user['header'] + user['data'] + msg_header + send_msg + msg_header2 + file_name)

    def main_server(self):
        while True:
            # Calls Unix select() system call or Windows select() WinSock call with three parameters:
            #   - rlist - sockets to be monitored for incoming data
            #   - wlist - sockets for data to be send to (checks if for example buffers are not full and socket is ready to send some data)
            #   - xlist - sockets to be monitored for exceptions (we want to monitor all sockets for errors, so we can use rlist)
            # Returns lists:
            #   - reading - sockets we received some data on (that way we don't have to check sockets manually)
            #   - writing - sockets ready for data to be send thru them
            #   - errors  - sockets with some exceptions
            # This is a blocking call, code execution will "wait" here and "get" notified in case any action should be taken

            self.read_sockets, _, self.exception_sockets = select.select(self.sockets_list, [], self.sockets_list)
            for notified_socket in self.read_sockets:
                if notified_socket == self.server_socket:
                    check1 = self.handle_new_client_file(notified_socket)
                    if check1 is False:
                        continue
                    # Else existing socket is sending a message
                else:
                    check2 = self.client_command(notified_socket)
                    if check2 is False:
                        continue

server1 = server()
server1.main_server()

