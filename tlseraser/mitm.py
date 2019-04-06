"""
This module opens the main sockets. Incoming connections are relayed to
a "socket mirror" and then to their original destination, assuming they have
been DNATed. TLS is enabled as needed.

The socket mirror runs in another network namespace and is used for the sole
reason of having an interface that the clear text is running through to use
with tcpdump.

TODO:
    - idea: instead of using markers, link streams by blocking new connections
"""

from tlseraser.args import args
import os
import socket
import select
import struct
import ssl
import subprocess
import threading
import time
import logging
log = logging.getLogger(__name__)

SO_ORIGINAL_DST = 80

ERASE_TLS = True  # streams must be linked for this to work
LINK_STREAMS = True  # 'False' untested - TODO
MARKER_LEN = 8
LISTEN_PORT = args.LPORT
MIRROR_IP = [args.M_LHOST, args.M_LPORT]
if args.TESTING:
    TEST_SERVICE = ['185.142.184.67', 443]
else:
    TEST_SERVICE = None

# If one end is performing the TLS handshake, we need to pause the data
# forwarding or the sockets will get mixed up
WAIT_FOR_HANDSHAKE = False

# keep track of streams with markers
streams = {}


class Stream(threading.Thread):
    def __init__(self,
                 server_sock,
                 client_sock,
                 marker,
                 orig_dest,
                 pre_mirror=False,
                 ):
        super(Stream, self).__init__()
        self.server_sock = server_sock
        self.client_sock = client_sock
        self.marker = marker
        self.pre_mirror = pre_mirror
        self.marker_str = "%x-%d" % (
            int.from_bytes(marker, "little"),
            self.pre_mirror,
        )
        if self.pre_mirror:
            self.orig_dest = orig_dest
        self.active = True
        self.init_sockets()
        if marker in streams:
            streams[marker][pre_mirror] = self
        else:
            streams[marker] = {pre_mirror: self}
        self.run()

    def init_sockets(self):
        '''Initialize member variables'''
        self.read_socks = [self.server_sock, self.client_sock]
        self.write_socks = []
        self.buffers = {
            self.server_sock: b"",
            self.client_sock: b"",
        }

    def peer_of(self, sock):
        '''Get the other socket'''
        if sock == self.server_sock:
            return self.client_sock
        return self.server_sock

    def disconnect(self, recurse=True):
        '''Disconnect everything'''
        self.active = False
        log.info('[%s] Disconnected' % self.marker_str)

    def run(self):
        '''The main loop'''
        log.debug("[%s] Start loop" % self.marker_str)
        while self.active:
            try:
                if WAIT_FOR_HANDSHAKE and not self.pre_mirror:
                    time.sleep(.1)
                else:
                    self.forward_data()
            #  except (ssl.SSLError, ssl.SSLEOFError) as e:
            #      log.error("SSLError: %s" % str(e))
            except (ConnectionResetError) as e:
                log.error("Connection lost (%s)" % str(e))
                self.disconnect()
            #  except ValueError as e:
            #      log.error(e)
            #      self.disconnect()

    def should_starttls(self, conn):
        '''Check if we want and can wrap the sockets in TLS now'''
        if self.pre_mirror:
            test_socket = self.server_sock
        else:
            test_socket = self.client_sock
        return (ERASE_TLS
                and conn == test_socket
                and not isinstance(conn, ssl.SSLSocket)
                and self.got_client_hello(conn)
                )

    def forward_data(self):
        '''Move data from one socket to the other'''
        #  log.debug('selecting sockets...')
        r, w, _ = select.select(self.read_socks, self.write_socks, [], 60)
        self.write_socks = []
        for conn in r:
            if conn.fileno() > 0:
                self.read_from_sock(conn)
        for conn in w:
            if conn.fileno() > 0:
                self.write_to_sock(conn)

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
                data = conn.recv(1000)
        except ConnectionResetError:
            log.debug("Connection Reset: %s" % conn)
            self.disconnect()
            return
        except ssl.SSLError as e:
            log.error(str(e))
            self.disconnect()
            return
        except ssl.SSLWantReadError:
            # can be ignored. data will be read next time
            return
        #  except OSError:
        #      log.info('connection reset by peer')
        #      self.disconnect()
        #      return False
        if data:
            #  log.debug('Read %d bytes' % len(data))
            self.buffers[conn] += data
            self.write_socks.append(self.peer_of(conn))
        else:
            log.info("[%s] Connection closed" % self.marker_str)
            self.disconnect()

    def write_to_sock(self, conn):
        '''Write data from a buffer to a socket'''
        #  log.debug('writing')
        data = self.buffers[self.peer_of(conn)]
        if data:
            try:
                c = conn.send(data)
                if c:
                    self.clear_peer_buffer(conn, c)
                    #  log.debug('Wrote %d byes' % c)
            except ssl.SSLWantReadError:
                # can be ignored
                # re-add socket to write_socks though to re-try the write
                self.write_socks.append(conn)
            except OSError as e:
                log.error(str(e))

    def clear_peer_buffer(self, conn, c):
        '''Clear buffer after data has been written to a socket'''
        peer = self.peer_of(conn)
        self.buffers[peer] = self.buffers[peer][c:]

    def get_paired_connection(self):
        '''Return the paired connection that shares the same marker'''
        if not LINK_STREAMS:
            log.error("Connections are not linked, use LINK_STREAMS=True")
            return None
        other_conn = not self.pre_mirror
        while other_conn not in streams[self.marker]:
            time.sleep(.1)
        return streams[self.marker][other_conn]

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
        except ValueError as e:
            log.error(e)

    def starttls(self):
        '''Wrap a connection and its counterpart inside TLS'''
        log.debug("Wrapping connection in TLS")
        peer = self.get_paired_connection()
        if peer:
            peer.client_sock = peer.tlsify_client(peer.client_sock)
            self.server_sock = self.tlsify_server(self.server_sock)
            do_tls_handshake(peer.client_sock)
            do_tls_handshake(self.server_sock)
            self.init_sockets()
            peer.init_sockets()

    def tlsify_server(self, conn):
        '''Wrap an incoming connection inside TLS'''
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
        log.debug("Retrieve original certificate and clone it")
        srv = self.get_paired_connection()
        peer = "%s:%d" % (srv.client_sock.getpeername())
        if CA_key:
            log.error("CA not yet implemented")
            #  cmd = ["./clone-cert.sh", peer, CA_key]  # TODO
        else:
            cmd = ["./clone-cert.sh", peer]
        try:
            fake_cert = subprocess.check_output(cmd,
                                                stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            log.error("%s - %s" % (str(e), e.stdout.decode()))
            return None
        return fake_cert.split(b'\n')[:2]

    def tlsify_client(self, conn):
        '''Wrap an outgoing connection inside TLS'''
        return ssl.wrap_socket(
            conn,
            ssl_version=ssl.PROTOCOL_TLS,
            do_handshake_on_connect=False,
        )


def original_dst(conn, pre_mirror=False):
    '''Find original destination of an incoming connection'''
    original_dst = conn.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    original_srv_port, original_srv_ip = struct.unpack("!2xH4s8x",
                                                       original_dst)
    original_srv_ip = "%d.%d.%d.%d" % (*original_srv_ip,)
    return original_srv_ip, original_srv_port


def open_connection(ip, port):
    '''Open a connection to the original destination'''
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    sock.setblocking(False)
    return sock


def create_marker_id():
    marker = os.urandom(MARKER_LEN)
    return marker


def accept(sock, pre_mirror=False):
    '''Accept incoming connection and pair it with one to original dest'''
    conn, addr = sock.accept()  # Should be ready
    orig_ip, orig_port = original_dst(conn, pre_mirror)
    log.info('accepted from %s:%d with original destination %s:%d' %
             (*addr, orig_ip, orig_port))
    conn.setblocking(False)
    if pre_mirror:
        other_conn = open_connection(*MIRROR_IP)
        marker = create_marker_id()
        other_conn.send(marker)
    else:
        # receive the marker first
        if LINK_STREAMS:
            r, _, _ = select.select([conn], [], [], 5)
            if r:
                marker = conn.recv(MARKER_LEN)
            else:
                log.error("Mirrored connection not received")
                return None, None, None
        else:
            marker = create_marker_id()
        if TEST_SERVICE:  # for testing. can be removed
            other_conn = open_connection(*TEST_SERVICE)
        else:  # TODO untested
            orig_dest = streams[marker][True].orig_dest
            other_conn = open_connection(orig_dest)
    log.debug('created connection pair [%x]: %s, %s' %
              (int.from_bytes(marker, "little"), conn, other_conn))
    Stream(conn, other_conn, marker, (orig_ip, orig_port), pre_mirror)


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


def start_data_forwarding(sock, pre_mirror=False):
    while True:
        accept(sock, pre_mirror)


def create_main_socket(ip, port):
    main_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    main_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    log.info('Start listening for incoming connections on port %d...' % port)
    main_sock.bind((ip, port))
    main_sock.listen(128)
    return main_sock


def main():
    port = LISTEN_PORT
    main_sock = create_main_socket('0.0.0.0', port)
    mirror_sock = create_main_socket('0.0.0.0', port+1)

    threading.Thread(
        target=start_data_forwarding,
        args=(main_sock, True),
        daemon=True
    ).start()

    threading.Thread(
        target=start_data_forwarding,
        args=(mirror_sock,),
        daemon=True
    ).start()

    try:
        subprocess.run(['./pcap-mirror.sh', '%d' % (port+1)])
    except KeyboardInterrupt:
        print('\r', end='')  # prevent '^C' on console
        log.info('Caught Ctrl-C, exiting')
