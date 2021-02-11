

import sys
import os
import time
import atexit
from signal import SIGINT, SIGTERM


import RoutingManager
import DataHandler
import RouteTable
import Transport

from conf import DEV, SET_TOPOLOGY_FLAG

import routing_logging


REDIRECT_TO = routing_logging.PATH_TO_LOGS + "crash_output.log"


PIDFILE_PATH = "/var/run/routing_daemon.pid"


ABSOLUTE_PATH = routing_logging.ABSOLUTE_PATH


TOPOLOGY_PATH = ABSOLUTE_PATH + "/topology.conf"


ROUTING_LOG = routing_logging.create_routing_log("routing.log", "root")


class Daemon:

    def __init__(self, pidfile, stdin="/dev/null", stdout=REDIRECT_TO, stderr=REDIRECT_TO):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.pidfile = pidfile

        f = open(REDIRECT_TO, "w")
        f.write("\n" + "-" * 100 + "\n")
        f.close()

    def daemonize(self):

        try:
            pid = os.fork()
            if pid > 0:

                sys.exit(0)
        except OSError, e:
            sys.stderr.write("fork
                             (e.errno, e.strerror))
            sys.exit(1)

        os.chdir(ABSOLUTE_PATH)
        os.setsid()
        os.umask(0)

        try:
            pid = os.fork()
            if pid > 0:

                sys.exit(0)
        except OSError, e:
            sys.stderr.write("fork
                             (e.errno, e.strerror))
            sys.exit(1)

        sys.stdout.flush()
        sys.stderr.flush()
        si = file(self.stdin, 'r')
        so = file(self.stdout, 'a+')

        se = file(self.stderr, 'a+')
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

        atexit.register(self.del_pid)
        pid = str(os.getpid())
        file(self.pidfile, 'w+').write("%s\n" % pid)

    def del_pid(self):
        os.remove(self.pidfile)

    def start(self):

        try:
            pf = file(self.pidfile, 'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None

        if pid:
            message = "pidfile %s already exist. Daemon already running?\n"
            sys.stderr.write(message % self.pidfile)
            sys.exit(1)

        self.daemonize()
        self.run()

    def stop(self):

        try:
            pf = file(self.pidfile, 'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None

        if not pid:
            message = "pidfile %s does not exist. Daemon not running?\n"
            sys.stderr.write(message % self.pidfile)
            return

        try:

            os.kill(pid, SIGINT)
            time.sleep(0.1)
            while 1:
                os.kill(pid, SIGTERM)
                time.sleep(0.1)
        except OSError, err:
            err = str(err)
            if err.find("No such process") > 0:
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
            else:
                print str(err)
                sys.exit(1)

    def restart(self):
        self.stop()
        self.start()

    def run(self):
        pass


class RoutingDaemon(Daemon):

    def run(self):

        routing_logging.init_log_thread()

        ROUTING_LOG.info("Running the routing instance...")

        node_mac = Transport.get_mac(DEV)

        topology_neighbors = self.get_topology_neighbors(node_mac)

        app_transport = Transport.VirtualTransport()

        raw_transport = Transport.RawTransport(
            DEV, node_mac, topology_neighbors)

        table = RouteTable.Table(node_mac)

        data_handler = DataHandler.DataHandler(
            app_transport, raw_transport, table)

        uds_server = RoutingManager.Manager(table)

        try:

            data_handler.run()

            uds_server.start()

            while True:
                packet = app_transport.recv_from_app()
                data_handler.app_handler.process_packet(packet)

        except KeyboardInterrupt:

            data_handler.stop_threads()

            uds_server.quit()

            routing_logging.stop_log_thread()

        return 0

    def get_topology_neighbors(self, node_mac):

        try:
            f = open(TOPOLOGY_PATH, "r")
        except IOError:

            ROUTING_LOG.warning("Could not open default topology file!!!")
            if SET_TOPOLOGY_FLAG:
                ROUTING_LOG.warning(
                    "All incoming frames will be filtered out!!!")
            return list()

        data = f.read()[:-1]
        entries = data.split("\n\n")
        for ent in entries:
            arr = ent.split("\n")
            if arr[0] == node_mac:
                neighbors = arr[1:]
                return neighbors

        return list()


if __name__ == "__main__":

    routing = RoutingDaemon(PIDFILE_PATH)

    if len(sys.argv) == 2:
        if 'start' == sys.argv[1]:
            routing.start()
        elif 'stop' == sys.argv[1]:
            routing.stop()
        elif 'restart' == sys.argv[1]:
            routing.restart()
        else:
            print "Unknown command"
            sys.exit(2)
        sys.exit(0)
    else:
        print "usage: %s start|stop|restart" % sys.argv[0]
        sys.exit(2)
