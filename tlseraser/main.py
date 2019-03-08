import socket
import select
import struct
import ssl
import threading
#  import time
import logging
log = logging.getLogger(__name__)


class Connection(threading.Thread):
    def __init__(self, server_sock, client_sock):
        super(Connection, self).__init__()
        self.server_sock = server_sock
        self.client_sock = client_sock
        self.init_sockets()
        self.active = True
        self.run()

    def init_sockets(self):
        self.read_socks = [self.server_sock, self.client_sock]
        self.write_socks = []
        self.buffers = {
            self.server_sock: b"",
            self.client_sock: b"",
        }

    def peer_of(self, sock):
        if sock == self.server_sock:
            return self.client_sock
        return self.server_sock

    def disconnect(self):
        self.active = False
        self.server_sock.close()
        self.client_sock.close()
        log.info('Disconnected')

    def run(self):
        log.debug("Start loop")
        while self.active:
            try:
                self.forward_data()
            #  except (ssl.SSLError, ssl.SSLEOFError) as e:
            #      log.error("SSLError: %s" % str(e))
            except (ConnectionResetError, OSError) as e:
                log.error("Connection lost (%s)" % str(e))
                self.disconnect()
            #  except ValueError as e:
            #      log.error(e)
            #      self.disconnect()

    def forward_data(self):
        log.debug('selecting sockets...')
        r, w, _ = select.select(self.read_socks, self.write_socks, [])
        self.write_socks = []
        for conn in r:
            self.read_from_sock(conn)
        for conn in w:
            self.write_to_sock(conn)

    def read_from_sock(self, conn):
        log.debug("reading")
        try:
            if (not isinstance(conn, ssl.SSLSocket)
                    and self.got_client_hello(conn)):
                self.starttls()
                return False
            else:
                data = conn.recv(1000)
        except ConnectionResetError:
            log.debug("Connection Reset: %s" % conn)
            self.disconnect()
        except ssl.SSLWantReadError:
            # can be ignored
            return
        #  except OSError:
            #  log.info('connection reset by peer')
            #  self.disconnect()
            #  return False
        if data:
            log.debug('Read %d bytes' % len(data))
            self.buffers[conn] += data
            self.write_socks.append(self.peer_of(conn))
        else:
            log.info("Connection closed")
            self.disconnect()

    def write_to_sock(self, conn):
        log.debug('writing')
        data = self.buffers[self.peer_of(conn)]
        if data:
            try:
                c = conn.send(data)
                if c:
                    self.buffers[self.peer_of(conn)] = b''
                    log.debug('Wrote %d byes' % c)
            except ssl.SSLWantReadError:
                # can be ignored
                # re-add socket to write_socks though
                self.write_socks.append(conn)

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
        # create new sockets
        self.server_sock = self.tlsify_server(self.server_sock)
        self.client_sock = self.tlsify_client(self.client_sock)
        self.init_sockets()

    def tlsify_server(self, conn):
        '''Wrap an incoming connection inside TLS'''
        #  cert = ssl.get_server_certificate(self.client_sock.getpeername())
        #  certfile = self.clone_cert(cert)
        return ssl.wrap_socket(conn,
                               server_side=True,
                               certfile="mitm.pem",
                               keyfile="mitm.key",
                               ssl_version=ssl.PROTOCOL_TLS,
                               do_handshake_on_connect=False,
                               )

    def clone_cert(self, cert, CA_key=None):
        '''Clone a certificate, i.e. preserve all fields except public key

        It will be self-signed unless the private key of a CA is given'''
        # TODO
        return "mitm.pem"

    def tlsify_client(self, conn):
        '''Wrap an outgoing connection inside TLS'''
        return ssl.wrap_socket(
            conn,
            do_handshake_on_connect=False,
        )


def original_dst(conn):
    '''Find original destination of an incoming connection'''
    SO_ORIGINAL_DST = 80
    original_dst = conn.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    original_srv_port, original_srv_ip = struct.unpack("!2xH4s8x",
                                                       original_dst)
    original_srv_ip = "%d.%d.%d.%d" % (*original_srv_ip,)
    return original_srv_ip, original_srv_port


def open_connection(ip, port, local_conn):
    '''Open a connection to the original destination'''
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ip = 'localhost'
    sock.connect((ip, port+1))
    sock.setblocking(False)
    return sock


def accept(sock):
    '''Accept incoming connection and pair it with one to original dest'''
    conn, addr = sock.accept()  # Should be ready
    orig_ip, orig_port = original_dst(conn)
    log.info('accepted from %s:%d with original destination %s:%d' %
             (*addr, orig_ip, orig_port))
    conn.setblocking(False)
    try:
        other_conn = open_connection(orig_ip, orig_port, conn)
        log.debug('created connection pair: %s, %s' % (conn, other_conn))
        return conn, other_conn
    except Exception as e:
        log.error('error while opening connection to original destination:'
                  ' %s' % e)
        conn.close()
        return None, None


def start_data_forwarding(sock):
    active = True
    try:
        while active:
            s, c = accept(sock)
            if s:
                Connection(s, c)
    except KeyboardInterrupt:
        print('\r', end='')  # prevent '^C' on console
        log.info('Caught Ctrl-C, exiting')
        active = False


def main():
    main_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    main_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    log.info('Start listening for incoming connections...')
    main_sock.bind(('localhost', 1234))
    main_sock.listen(128)
    #  main_sock.setblocking(False)

    start_data_forwarding(main_sock)
