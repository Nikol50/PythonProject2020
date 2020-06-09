import socket
import errno
from tkinter import *
from Asymmetric_rsa import asymmetric
from Symmetric import symmetric
import datetime
import os
import sys

class client_file:
    def __init__(self, my_username=""):
        self.HEADER_LENGTH = 10
        self.IP = "127.0.0.1"
        self.PORT = 9999
        self.my_username = my_username
        self.rsa = asymmetric()
        self.rsa = asymmetric()
        private_key, public_key = self.rsa.generating_keys()
        self.rsa.storing_keys(private_key, public_key)
        self.private_key, self.public_key = self.rsa.Reading_keys(private_key, public_key)
        self.sym = symmetric()
        self.key, self.iv = self.sym.generating_key_and_iv()
        self.directory = ""
        self.main_file_name = "work files"
        # Create a socket
        # socket.AF_INET - address family, IPv4, some otehr possible are AF_INET6, AF_BLUETOOTH, AF_UNIX
        # socket.SOCK_STREAM - TCP, conection-based, socket.SOCK_DGRAM - UDP, connectionless, datagrams, socket.SOCK_RAW - raw IP packets
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect()
        self.public_key_server_get = self.username_and_header_and_keys_send()

    def connect(self):
        # Connect to a given ip and port
        self.client_socket.connect((self.IP, self.PORT))
        # Set connection to non-blocking state, so .recv() call won;t block, just return some exception we'll handle
        self.client_socket.setblocking(1)

    def set_directory(self, new):
        self.directory = new
        self.today_file = str(self.get_date_time())
        self.open_file = str(self.directory + "\\" + self.main_file_name + "\\" + self.today_file)
        if not os.path.exists(self.open_file):
            os.makedirs(self.open_file)
        else:
            print("error")

    def encrypting_symmetric_key_iv(self, key, iv, public_key_server_get):
        key_enc = self.rsa.encryption(public_key_server_get, key)
        iv_enc = self.rsa.encryption(public_key_server_get, iv)
        key_enc_header = f"{len(key_enc):<{self.HEADER_LENGTH}}".encode('latin-1')
        iv_enc_header = f"{len(iv_enc):<{self.HEADER_LENGTH}}".encode('latin-1')
        return key_enc, iv_enc, key_enc_header, iv_enc_header

    def username_and_header_and_keys_send(self):
        username = self.my_username.encode('latin-1')
        username_header = f"{len(username):<{self.HEADER_LENGTH}}".encode('latin-1')
        self.client_socket.send(username_header + username + self.public_key)
        print("send username and public key")
        public_key_server = self.client_socket.recv(1024)
        public_key_server_get1 = self.rsa.read_public_key_server(public_key_server)
        enc_key, enc_iv, header_key, header_iv = self.encrypting_symmetric_key_iv(self.key, self.iv, public_key_server_get1)
        self.client_socket.send(header_key + header_iv + enc_key + enc_iv)
        return public_key_server_get1

    def get_date_time(self):
        mylist = []
        today = datetime.date.today()
        mylist.append(today)
        return mylist[0]

    def file_to_server(self, command, file_name="", send_to="", userid ="", username="", password=""):
        try:
            print(command)
            if command == "login":
                commad_enc = self.rsa.encryption(self.public_key_server_get, command.encode('latin-1'))
                userid_enc = self.rsa.encryption(self.public_key_server_get, userid.encode('latin-1'))
                username_enc = self.rsa.encryption(self.public_key_server_get,  username.encode('latin-1'))
                password_enc = self.rsa.encryption(self.public_key_server_get,  password.encode('latin-1'))
                command_header = f"{len(commad_enc):<{self.HEADER_LENGTH}}".encode('latin-1')
                userid_header = f"{len(userid_enc):<{self.HEADER_LENGTH}}".encode('latin-1')
                username_header = f"{len(username_enc):<{self.HEADER_LENGTH}}".encode('latin-1')
                password_header = f"{len(password_enc):<{self.HEADER_LENGTH}}".encode('latin-1')
                self.client_socket.send(command_header + commad_enc + userid_header + userid_enc + username_header +
                                    username_enc + password_header + password_enc)
            if command == "register":
                commad_enc = self.rsa.encryption(self.public_key_server_get, command.encode('latin-1'))
                userid_enc = self.rsa.encryption(self.public_key_server_get, userid.encode('latin-1'))
                username_enc = self.rsa.encryption(self.public_key_server_get, username.encode('latin-1'))
                password_enc = self.rsa.encryption(self.public_key_server_get, password.encode('latin-1'))
                command_header = f"{len(commad_enc):<{self.HEADER_LENGTH}}".encode('latin-1')
                userid_header = f"{len(userid_enc):<{self.HEADER_LENGTH}}".encode('latin-1')
                username_header = f"{len(username_enc):<{self.HEADER_LENGTH}}".encode('latin-1')
                password_header = f"{len(password_enc):<{self.HEADER_LENGTH}}".encode('latin-1')
                self.client_socket.send(command_header + commad_enc + userid_header + userid_enc + username_header +
                                    username_enc + password_header + password_enc)
            if command == "log out":
                commad_enc = self.rsa.encryption(self.public_key_server_get, command.encode('latin-1'))
                command_header = f"{len(commad_enc):<{self.HEADER_LENGTH}}".encode('latin-1')
                self.client_socket.send(command_header + commad_enc)

            if command == "list":
                commad_enc = self.rsa.encryption(self.public_key_server_get, command.encode('latin-1'))
                command_header = f"{len(commad_enc):<{self.HEADER_LENGTH}}".encode('latin-1')
                self.client_socket.send(command_header + commad_enc)

            if file_name and command == "new file":
                # If message is not empty - send it
                commad_enc = self.rsa.encryption(self.public_key_server_get, command.encode('latin-1'))
                command_header = f"{len(commad_enc):<{self.HEADER_LENGTH}}".encode('latin-1')

                data = self.sym.read_file(file_name)
                enc_file = self.sym.encrypt_file(self.key, self.iv, data)
                print("encryption: " + str(enc_file))
                # Encode message to bytes, prepare header and convert to bytes, like for username above, then send
                message_header = f"{len(enc_file):<{self.HEADER_LENGTH}}".encode('latin-1')

                name = self.rsa.encryption(self.public_key_server_get, file_name.encode('latin-1'))
                message_header2 = f"{len(name):<{self.HEADER_LENGTH}}".encode('latin-1')

                send_to = self.rsa.encryption(self.public_key_server_get, send_to.encode('latin-1'))
                message_header3 = f"{len(send_to):<{self.HEADER_LENGTH}}".encode('latin-1')

                self.client_socket.send(command_header + commad_enc + message_header + enc_file + message_header2 + name +
                                    message_header3 + send_to)
        except:
            return False


    def msg_to_server(self):
        message = input(f'{self.my_username} > ')
        # If message is not empty - send it
        if message:
            message1 = self.rsa.encryption(self.public_key_server_get, message.encode())
            # Encode message to bytes, prepare header and convert to bytes, like for username above, then send
            message_header = f"{len(message1):<{self.HEADER_LENGTH}}".encode('latin-1')
            self.client_socket.send(message_header + message1)

    def receive_list_connected(self):
        self.client_socket.setblocking(True)
        list_header = self.client_socket.recv(self.HEADER_LENGTH)
        if len(list_header) == 0:
            print('Connection closed by the server')
            return False
        # Convert header to int value
        list_length = int(list_header.decode('latin-1').strip())
        # Receive and decode username
        string_list = self.client_socket.recv(list_length).decode('latin-1')
        list = string_list.split("*")
        return list

    def answer_login_register(self):
        answer_header = self.client_socket.recv(self.HEADER_LENGTH)
        if not len(answer_header):
            print('Connection closed by the server')
            sys.exit()
        # Convert header to int value
        answer_length = int(answer_header.decode('latin-1').strip())
        # Receive and decode username
        answer = self.client_socket.recv(answer_length).decode('latin-1')
        print(answer)
        if answer == "Yes":
            return True
        else:
            return False


    def recieve_files(self):
        try:
            self.client_socket.setblocking(False)

            # Now we want to loop over received messages (there might be more than one) and print them
            while True:

                # Receive our "header" containing username length, it's size is defined and constant
                username_header = self.client_socket.recv(self.HEADER_LENGTH)

                # If we received no data, server gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
                if not len(username_header):
                    print('Connection closed by the server')
                    return False

                # Convert header to int value
                username_length = int(username_header.decode('latin-1').strip())

                # Receive and decode username
                username = self.client_socket.recv(username_length).decode('latin-1')

                # Receive and decode username
                # Now do the same for message (as we received username, we received whole message, there's no need to check if it has any length)
                message_header = self.client_socket.recv(self.HEADER_LENGTH)
                message_length = int(message_header.decode('latin-1').strip())
                message = self.client_socket.recv(message_length)
                decrypt_data = self.sym.decrypt_file(self.key, self.iv, message)

                message_header2 = self.client_socket.recv(self.HEADER_LENGTH)
                message_length2 = int(message_header2.decode('latin-1').strip())
                file_name = self.client_socket.recv(message_length2)
                #file_name = self.rsa.decryption(self.private_key, file_name)
                file_name = file_name.decode('latin-1')
                file_name = file_name.split("\\")
                file_path = str(self.open_file + "\\" + str(file_name[-1]))
                self.sym.output_file(decrypt_data, file_path)
                # Print message
                message = str(message)
                print(f'{username} send file > {self.open_file}')
                return username, str(file_name[-1])

        except IOError as e:
            # This is normal on non blocking connections - when there are no incoming data error is going to be raised
            # Some operating systems will indicate that using AGAIN, and some using WOULDBLOCK error code
            # We are going to check for both - if one of them - that's expected, means no incoming data, continue as normal
            # If we got different error code - something happened
            if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                print('Reading error: {}'.format(str(e)))
                sys.exit()
                return False
            # We just did not receive anything
        except Exception as e:
            # Any other exception - something happened, exit
            print('Reading error: {}'.format(str(e)))
            return False

    def client_log_out(self):
        self.client_socket.close()

#client1=client_file()
#while True:
#    client1.file_to_server()
#    client1.recieve_files()

