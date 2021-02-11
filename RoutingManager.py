

import threading
import socket
import pickle
import os

import routing_logging

MANAGER_LOG = routing_logging.create_routing_log(
    "routing.manager.log", "manager")


class Manager(threading.Thread):
    def __init__(self, table):
        super(Manager, self).__init__()

        self.running = False

        self.table = table

        self.server_address = "/tmp/uds_socket"

        self.FNULL = open(os.devnull, "w")

        if os.path.exists(self.server_address):
            os.remove(self.server_address)

        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.server_address)

        self.sock.listen(5)
        self.connection = None

    def run(self):
        self.running = True
        self.connection = self.sock.accept()[0]

        while self.running:
            request = self.connection.recv(1024)

            MANAGER_LOG.debug("Got request from UDS socket: %s", request)

            request = request.split(":")
            if request[0] == "0":
                self.flush_table()

            elif request[0] == "1":
                self.flush_neighbors()

            elif request[0] == "2":
                self.get_table()

            elif request[0] == "3":
                self.get_neighbors()

            elif request[0] == "":
                MANAGER_LOG.info(
                    "Got empty string from socket. Client has been disconnected.")

                self.connection = self.sock.accept()[0]

            else:
                MANAGER_LOG.info("Unknown command! %s", request[0])

        MANAGER_LOG.debug("MAIN LOOP IS FINISHED.")

    def flush_table(self):
        pass

    def flush_neighbors(self):
        pass

    def get_table(self):
        table_data = self.table.get_list_of_entries()

        self.connection.sendall(pickle.dumps(table_data))

    def get_neighbors(self):
        neighbors = self.table.get_neighbors_l3_addresses()

        self.connection.sendall(pickle.dumps(neighbors))

    def quit(self):
        self.running = False
        self.sock.close()
