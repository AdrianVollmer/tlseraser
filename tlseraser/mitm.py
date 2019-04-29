"""
This module opens the main sockets. Incoming connections are relayed to
a "socket mirror" and then to their original destination, assuming they have
been DNATed. TLS is enabled as needed.

The socket mirror runs in another network namespace and is used for the sole
reason of having an interface that the clear text is running through to use
with tcpdump.

"""

#                 S1  S2            S5  S6
#  source ---->----o  o              o  o---->---- original destination
#                      \            /
#                       \          /                        namespace 1
#  ====================================================================
#                         \      /                          namespace 2
#                          \    /
#                           o  o
#                          S3  S4
#
# Terminate TLS at S1, re-establish it at S6

from tlseraser.args import args
import os
import sys
import socket
import select
import struct
import ssl
import subprocess
import netns
import random
import threading
import time
import logging
log = logging.getLogger(__name__)

SO_ORIGINAL_DST = 80

ERASE_TLS = True
LISTEN_PORT = args.LPORT
if args.TESTING:
    TEST_SERVICE = ('ptav.sy.gs', 443)
else:
    TEST_SERVICE = None

SUBNET = args.MIRROR_SUBNET
DEVNAME = 'noTLS'
NETNS = 'mirror'

# If one end is performing the TLS handshake, we need to pause the data
# forwarding or the sockets will get mixed up
WAIT_FOR_HANDSHAKE = False

open_ports = {}
port_id = 0  # counter for referring to open ports between threads


class ThreadWithReturnValue(threading.Thread):
    def __init__(self, group=None, target=None, name=None,
                 args=(), kwargs={}, Verbose=None, daemon=True):
        threading.Thread.__init__(self, group, target, name, args, kwargs,
                                  daemon=daemon)
        self._return = None

    def run(self):
        if self._target is not None:
            self._return = self._target(*self._args, **self._kwargs)

    def join(self, *args):
        threading.Thread.join(self, *args)
        return self._return


class Forwarder(threading.Thread):
    def __init__(self, sockets, orig_dest):
        super(Forwarder, self).__init__()
        self.id = "%08x" % random.randint(0, 2**32)
        self.active = True
        self.sockets = sockets
        log.info("Connecting to %s:%d..." % orig_dest)
        try:
            S6 = open_connection(*orig_dest)
            self.sockets.append(S6)
        except Exception:
            log.exception("[%s] Exception while connecting to original "
                          "destination", self.id)
            for s in self.sockets:
                s.close()
            self.active = False

        self.init_sockets()
        self.key_cert = None

    def init_sockets(self):
        '''Initialize member variables'''
        self.buffer = {}
        for s in self.sockets:
            self.buffer[s] = b''
        self.peer = {
            self.sockets[0]: self.sockets[1],
            self.sockets[1]: self.sockets[0],
            self.sockets[2]: self.sockets[3],
            self.sockets[3]: self.sockets[2],
            self.sockets[4]: self.sockets[5],
            self.sockets[5]: self.sockets[4],
        }
        self.read_socks = self.sockets
        self.write_socks = []

    def disconnect(self, conn):
        '''Disconnect a socket and its peer'''
        self.active = False
        self.peer[conn].close()
        self.read_socks.remove(conn)
        self.read_socks.remove(self.peer[conn])

    def run(self):
        '''The main loop'''
        log.debug("[%s] Start loop" % self.id)
        while self.active:
            #  try:
            if WAIT_FOR_HANDSHAKE:
                time.sleep(.1)
            else:
                self.forward_data()
            #  except (ssl.SSLError, ssl.SSLEOFError) as e:
            #      log.error("SSLError: %s" % str(e))
            #  except (ConnectionResetError) as e:
            #      log.error("Connection lost (%s)" % str(e))
            #      self.disconnect()
            #  except ValueError as e:
            #      log.error(e)
            #      self.disconnect()

    def should_starttls(self, conn):
        '''Check if we want and can wrap the sockets in TLS now'''
        return (ERASE_TLS
                and conn == self.sockets[0]
                and not isinstance(conn, ssl.SSLSocket)
                and self.got_client_hello(conn)
                )

    def forward_data(self):
        '''Move data from one socket to the other'''
        #  log.debug('selecting sockets...')
        r, w, _ = select.select(self.read_socks, self.write_socks, [], 60)
        for conn in w:
            self.write_to_sock(conn)
        self.write_socks = []
        for conn in r:
            self.read_from_sock(conn)

    def read_from_sock(self, conn):
        '''Read data from a socket to a buffer'''
        #  log.debug("reading")
        global WAIT_FOR_HANDSHAKE
        try:
            if self.should_starttls(conn):
                WAIT_FOR_HANDSHAKE = True
                self.starttls()
                WAIT_FOR_HANDSHAKE = False
                return
            else:
                data = conn.recv(1024)
        except (ConnectionResetError, OSError):
            log.debug("[%s] Connection reset: %s" % (self.id, conn))
            self.disconnect(conn)
            return
        except ssl.SSLWantReadError:
            # can be ignored. data will be read next time
            return False
        except ssl.SSLError:
            log.exception("[%s] Exception while reading" % self.id)
            return False
        if data:
            #  log.debug('Read %d bytes' % len(data))
            self.buffer[self.peer[conn]] += data
            self.write_socks.append(self.peer[conn])
        else:
            log.info("[%s] Connection closed" % self.id)
            self.disconnect(conn)

    def write_to_sock(self, conn):
        '''Write data from a buffer to a socket'''
        #  log.debug('writing')
        data = self.buffer[conn]
        if data:
            try:
                c = conn.send(data)
                if c:
                    self.buffer[conn] = data[c:]
                    #  log.debug('Wrote %d byes' % c)
            except ssl.SSLWantReadError:
                # can be ignored
                # re-add socket to write_socks though to re-try the write
                self.write_socks.append(conn)
            except OSError:
                log.exception("[%s] Exception while writing" % self.id)

    def got_client_hello(self, sock):
        '''Peek inside the connection and return True if we see a
        Client Hello'''
        try:
            firstbytes = sock.recv(3, socket.MSG_PEEK)
            return (len(firstbytes) == 3
                    and firstbytes[0] == 0x16
                    and firstbytes[1:3] in [b"\x03\x00",
                                            b"\x03\x01",
                                            b"\x03\x02",
                                            b"\x03\x03",
                                            b"\x02\x00"]
                    )
        except ValueError:
            log.exception("[%s] Exception while looking for client hello" %
                          self.id)

    def starttls(self):
        '''Wrap a connection and its counterpart inside TLS'''
        log.debug("[%s] Wrapping connection in TLS" % self.id)
        self.sockets[0] = self.tlsify_server(self.sockets[0])
        self.sockets[5] = self.tlsify_client(self.sockets[5])
        do_tls_handshake(self.sockets[0])
        do_tls_handshake(self.sockets[5])
        self.init_sockets()

    def tlsify_server(self, conn):
        '''Wrap an incoming connection inside TLS'''
        keyfile, certfile = self.get_cached_cert()
        if not (keyfile and certfile):
            keyfile, certfile = self.clone_cert()
        #  certfile, keyfile = "mitm.pem mitm.key".split()
        return ssl.wrap_socket(conn,
                               server_side=True,
                               certfile=certfile,
                               keyfile=keyfile,
                               ssl_version=ssl.PROTOCOL_TLS,
                               do_handshake_on_connect=False,
                               )

    def clone_cert(self, CA_key=None):
        '''Clone a certificate, i.e. preserve all fields except public key

        It will be self-signed unless the private key of a CA is given'''
        log.debug("[%s] Retrieve original certificate and clone it" %
                  self.id)
        srv = self.sockets[5]
        peer = "%s:%d" % (srv.getpeername())
        if CA_key:
            #  log.error("[%s] CA not yet implemented" % self.id)
            cmd = ["./clone-cert.sh", peer, CA_key]  # TODO
        else:
            cmd = [os.path.join(sys.path[0], "clone-cert.sh"), peer]
        try:
            fake_cert = subprocess.check_output(cmd,
                                                stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            log.error("[%s] %s - %s" % (self.id, str(e), e.stdout.decode()))
            return None
        return fake_cert.split(b'\n')[:2]

    def get_cached_cert(self):
        '''Returns a cached certificate. Result is 'None, None' if it hasn't
        been cached yet'''
        srv = self.sockets[5]
        peer = "%s:%d" % (srv.getpeername())
        cert_filename = os.path.join('/tmp/', '%s_0' % peer)
        key_filename = cert_filename + '.key'
        cert_filename = cert_filename + '.cert'
        if os.path.exists(cert_filename) and os.path.exists(key_filename):
            log.debug("Get cached certificate for %s" % peer)
            return key_filename, cert_filename
        return None, None

    def tlsify_client(self, conn):
        '''Wrap an outgoing connection inside TLS'''
        return ssl.wrap_socket(
            conn,
            ssl_version=ssl.PROTOCOL_TLS,
            do_handshake_on_connect=False,
        )


def do_tls_handshake(s):
    while True:
        try:
            s.do_handshake()
            break
        except ssl.SSLError as err:
            if err.args[0] == ssl.SSL_ERROR_WANT_READ:
                select.select([s], [], [])
            elif err.args[0] == ssl.SSL_ERROR_WANT_WRITE:
                select.select([], [s], [])
            else:
                raise


def original_dst(conn):
    '''Find original destination of an incoming connection'''
    original_dst = conn.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    original_srv_port, original_srv_ip = struct.unpack("!2xH4s8x",
                                                       original_dst)
    original_srv_ip = "%d.%d.%d.%d" % (*original_srv_ip,)
    return original_srv_ip, original_srv_port


def open_connection(ip, port, netns_name=None):
    '''Open a connection to the original destination'''
    if netns_name:
        sock = netns.socket(
            netns.get_ns_path(nsname=netns_name),
            socket.AF_INET,
            socket.SOCK_STREAM
        )
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    sock.setblocking(False)
    return sock


def accept(sock):
    '''Accept incoming connection (S1) and create the other sockets'''
    global port_id
    S1, addr = sock.accept()  # Should be ready
    orig_dest = original_dst(S1)
    if TEST_SERVICE:
        orig_dest = TEST_SERVICE
    log.info('Accepted from %s:%d with original destination %s:%d' %
             (*addr, *orig_dest))
    S1.setblocking(False)

    t1 = ThreadWithReturnValue(
        target=accept_connection,
        args=(port_id, SUBNET + '.1', 0, NETNS),
        daemon=True,
    )
    port_id += 1
    t1.start()

    t2 = ThreadWithReturnValue(
        target=accept_connection,
        args=(port_id, SUBNET + '.254', 0, None),
        daemon=True,
    )
    port_id += 1
    t2.start()

    while True:
        try:
            S2 = open_connection(*(open_ports[port_id-2]))
            break
        except (ConnectionRefusedError, KeyError):
            time.sleep(.05)
    while True:
        try:
            S4 = open_connection(*(open_ports[port_id-1]), NETNS)
            break
        except (ConnectionRefusedError, KeyError):
            time.sleep(.05)

    S3 = t1.join()
    S5 = t2.join()
    return Forwarder([S1, S2, S3, S4, S5], orig_dest)


def start_data_forwarding(sock):
    while True:
        log.debug("Waiting for connection")
        f = accept(sock)
        if f:
            f.start()


def accept_connection(port_id, ip, port=0, netns_name=None):
    if netns_name:
        sock = netns.socket(
            netns.get_ns_path(nsname=netns_name),
            socket.AF_INET,
            socket.SOCK_STREAM,
        )
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((ip, port))
    log.info('Start listening for incoming connections on %s:%d...' %
             sock.getsockname())
    global open_ports
    open_ports[port_id] = sock.getsockname()
    sock.listen(2)
    conn, addr = sock.accept()
    log.debug("Accepted from %s:%d" % (*addr,))
    return conn


def run_steps(steps, ignore_errors=False):
    parameters = {
        "netns": NETNS,
        "devname": DEVNAME,
        "subnet": SUBNET,
    }
    for step in steps:
        try:
            subprocess.check_output((step % parameters).split(),
                                    stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            if ignore_errors:
                pass
            else:
                print(e.output.decode())
                raise


setup_ns = [
    # create a test network namespace:
    'ip netns add %(netns)s',
    # create a pair of virtual network interfaces ($devname-a and $devname):
    'ip link add %(devname)s-a type veth peer name %(devname)s',
    # change the active namespace of the $devname-a interface:
    'ip link set %(devname)s-a netns %(netns)s',
    # configure the IP addresses of the virtual interfaces:
    'ip netns exec %(netns)s ip link set %(devname)s-a up',
    'ip netns exec %(netns)s ip addr add %(subnet)s.1/23 dev %(devname)s-a',
    'ip link set %(devname)s up',
    'ip addr add %(subnet)s.254/24 dev %(devname)s',
    'ip netns exec %(netns)s ip route add default via '
    '%(subnet)s.254 dev %(devname)s-a'
]


teardown_ns = [
    'ip link del %(devname)s',
    'ip netns del %(netns)s',
]


def main():
    lport = args.LPORT
    lhost = args.LHOST
    run_steps(setup_ns)
    main_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    main_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    log.info('Start listening for incoming connections on %s:%d...' %
             (lhost, lport))
    main_sock.bind((lhost, lport))
    main_sock.listen(128)

    try:
        start_data_forwarding(main_sock)
    except KeyboardInterrupt:
        print('\r', end='')  # prevent '^C' on console
        log.info('Caught Ctrl-C, exiting...')
