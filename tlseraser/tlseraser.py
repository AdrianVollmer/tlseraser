#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  Copyright (c) 2019 Adrian Vollmer
#
#  Permission is hereby granted, free of charge, to any person obtaining a
#  copy of this software and associated documentation files (the
#  "Software"), to deal in the Software without restriction, including
#  without limitation the rights to use, copy, modify, merge, publish,
#  distribute, sublicense, and/or sell copies of the Software, and to permit
#  persons to whom the Software is furnished to do so, subject to the
#  following conditions:
#
#  The above copyright notice and this permission notice shall be included
#  in all copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
#  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
#  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
#  NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
#  DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
#  OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
#  USE OR OTHER DEALINGS IN THE SOFTWARE.

"""
This module opens the main socket. Incoming connections are relayed to
a "socket mirror" and then to their original destination, assuming they have
been DNATed. TLS is enabled as needed.

The socket mirror runs in another network namespace and is used for the sole
reason of having an interface that the clear text is running through to use
with tcpdump.

"""

__version__ = '0.0.4'
__author__ = 'Adrian Vollmer'


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

import atexit
import os
import errno
import socket
import select
import shutil
import signal
import struct
import ssl
import subprocess
import netns
import random
import threading
import time
import logging
log = logging.getLogger(__name__)

_SO_ORIGINAL_DST = 80

_open_ports = {}
_port_id = 0  # counter for referring to open ports between threads
_cert_locks = []


# find clone-cert.sh executable
CLONE_CERT = None
SCRIPT_PATH = os.path.dirname(__file__)
for p in ['clone-cert.sh',
          os.path.join(SCRIPT_PATH, 'bin/clone-cert.sh'),
          os.path.join(SCRIPT_PATH, '../bin/clone-cert.sh')]:
    if shutil.which(p):
        CLONE_CERT = p
        break
if not CLONE_CERT:
    raise FileNotFoundError(errno.ENOENT,
                            os.strerror(errno.ENOENT),
                            'clone-cert.sh')


def acquire_cert_lock(peer):
    while peer in _cert_locks:
        time.sleep(.1)
    _cert_locks.append(peer)
    return peer


def release_cert_lock(lock):
    global _cert_locks
    _cert_locks.remove(lock)


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
    def __init__(self, sockets, orig_dest, erase_tls=True):
        super(Forwarder, self).__init__()
        self.id = "%08x" % random.randint(0, 2**32)
        self.erase_tls = erase_tls
        self.active = True
        self.sockets = sockets
        log.info("[%s] Connecting to %s:%d..." % (self.id, *orig_dest))
        try:
            S6 = _open_connection(*orig_dest)
            self.sockets.append(S6)
        except Exception:
            log.exception("[%s] Exception while connecting to original "
                          "destination", self.id)
            for s in self.sockets:
                s.close()
            self.active = False
            return None

        self.sni = None
        self.init_sockets()
        self.key_cert = None

    def init_sockets(self):
        '''Initialize member variables'''
        self.buffer = {}
        for s in self.sockets:
            self.buffer[s] = b''
            try:
                s.setblocking(0)
            except AttributeError:
                pass
        self.peer = {
            self.sockets[0]: self.sockets[1],
            self.sockets[1]: self.sockets[0],
            self.sockets[2]: self.sockets[3],
            self.sockets[3]: self.sockets[2],
            self.sockets[4]: self.sockets[5],
            self.sockets[5]: self.sockets[4],
        }
        self.read_socks = self.sockets
        self.signal_pipe = os.pipe()
        self.read_socks.append(self.signal_pipe[0])
        self.write_socks = []

    def disconnect(self, s):
        '''Disconnect a socket and its peer'''
        log.debug("[%s] Disconnecting" % self.id)
        try:
            s.close()
            self.peer[s].close()
            self.read_socks.remove(s)
            self.read_socks.remove(self.peer[s])
        except (KeyError, ValueError):
            pass
        self.active = False
        # check if buffers are all empty
        for key, val in self.buffer.items():
            if val:
                self.active = True
                break
            # sending something to signal pipe so select call returns
        os.write(self.signal_pipe[1], b'_')

    def run(self):
        '''The main loop'''
        log.debug("[%s] Start loop" % self.id)
        while self.active:
            self.forward_data()

    def should_starttls(self, conn):
        '''Check if we want and can wrap the sockets in TLS now'''
        return (self.erase_tls
                and conn == self.sockets[0]
                and not isinstance(conn, ssl.SSLSocket)
                and self.got_client_hello(conn)
                )

    def forward_data(self):
        '''Move data from one socket to the other'''
        r, w, _ = select.select(self.read_socks, self.write_socks, [], 1)
        self.write_socks = []
        for s in w:
            self.write_from_buffer(s)
        for s in r:
            if s == self.signal_pipe[0]:
                os.read(s, 1)
            else:
                if not self.read_from_sock(s):
                    break

    def tamper(self, sock):
        if sock == self.sockets[2]:
            return self.tamper_in(sock)
        elif sock == self.sockets[3]:
            return self.tamper_out(sock)
        else:
            return True

    def tamper_in(self, s):
        return True

    def tamper_out(self, s):
        return True

    def recv_all(self, sock):
        data = sock.recv(1024**2)
        return data

    def buffer_data(self, sock, data):
        if data:
            self.buffer[self.peer[sock]] += data
            if self.tamper(self.peer[sock]):
                self.write_socks.append(self.peer[sock])
        else:
            self.disconnect(sock)

    def write_from_buffer(self, sock):
        try:
            if self.buffer[sock]:
                c = sock.send(self.buffer[sock])
                self.buffer[sock] = self.buffer[sock][c:]
        except (ConnectionResetError, BrokenPipeError):
            self.disconnect(sock)

    def read_from_sock(self, s):
        '''Read data from a socket to a buffer'''
        #  log.debug("reading")
        try:
            if self.should_starttls(s):
                self.starttls()
                return False
            else:
                data = self.recv_all(s)
                self.buffer_data(s, data)
        except ssl.SSLWantReadError:
            # can be ignored. data will be read next time
            return False
        except ssl.SSLError as err:
            if err.reason == "TLSV1_ALERT_UNKNOWN_CA":
                log.error(
                    "[%s] Client does not trust our cert (while reading)"
                    % self.id)
            else:
                log.exception("[%s] Exception while reading" % self.id)
            self.disconnect(s)
            return False
        except (ConnectionResetError, OSError):
            log.debug("[%s] Connection reset" % self.id)
            self.disconnect(s)
            return False
        return True

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

    def get_peer(self, sock):
        peer = "%s:%d" % (sock.getpeername())
        if self.sni:
            peer = "%s@%s" % (self.sni, peer)
        return peer

    def got_client_hello(self, sock):
        '''Peek inside the connection and return True if we see a
        Client Hello'''
        log.debug("[%s] Checking for TLS client hello" % self.id)
        try:
            firstbytes = sock.recv(5, socket.MSG_PEEK)
            result = (len(firstbytes) >= 3
                      and firstbytes[0] == 0x16
                      and firstbytes[1:3] in [b"\x03\x00",
                                              b"\x03\x01",
                                              b"\x03\x02",
                                              b"\x03\x03",
                                              b"\x02\x00"]
                      )
            if result:
                from tlseraser.tlsparser import get_sni
                length = struct.unpack("!H", firstbytes[3:5])[0]
                tls_client_hello = sock.recv(5+length, socket.MSG_PEEK)
                self.sni = get_sni(tls_client_hello)
                log.info("[%s] SNI: %s" % (self.id, self.sni))
            return result
        except ValueError:
            log.exception("[%s] Exception while looking for client hello" %
                          self.id)

    def starttls(self):
        '''Wrap a connection and its counterpart inside TLS'''
        log.debug("[%s] Wrapping connection in TLS" % self.id)
        s0 = self.sockets[0]
        s5 = self.sockets[5]
        self.sockets[0] = self.tlsify_server(self.sockets[0])
        self.sockets[5] = self.tlsify_client(self.sockets[5])
        if not self.do_tls_handshake(self.sockets[5]):
            self.disconnect(s5)
        if not self.do_tls_handshake(self.sockets[0]):
            self.disconnect(s0)
        self.init_sockets()

    def tlsify_server(self, conn):
        '''Wrap an incoming connection inside TLS'''
        peer = self.get_peer(conn)
        lock = acquire_cert_lock(peer)
        # TODO keep using one issuer
        keyfile, certfile = self.get_cached_cert()
        if not (keyfile and certfile):
            try:
                keyfile, certfile = self.clone_cert()
            except Exception:
                log.exception("Failed to clone cert, using an obviously "
                              "self-signed one")
        if not (keyfile and certfile):
            path = os.path.realpath(__file__)
            keyfile = os.path.join(path, 'key.pem')
            certfile = os.path.join(path, 'cert.pem')
            log.warning("[%] Use fallback certificate" % self.id)
        release_cert_lock(lock)
        context = ssl.SSLContext()
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        return context.wrap_socket(conn,
                                   server_side=True,
                                   do_handshake_on_connect=False,
                                   )

    def clone_cert(self, CA_key=None):
        '''Clone a certificate, i.e. preserve all fields except public key

        It will be self-signed unless the private key of a CA is given'''
        peer = self.get_peer(self.sockets[5])
        log.debug("[%s] Retrieve original certificate and clone it (%s)" %
                  (self.id, peer))
        if CA_key:
            log.error("[%s] CA not yet implemented" % self.id)
            #  cmd = [CLONE_CERT, peer, CA_key]  # TODO
        else:
            cmd = [CLONE_CERT, '--reuse-keys', peer]
        try:
            fake_cert = subprocess.check_output(cmd,
                                                stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            log.error("[%s] %s - %s" % (self.id, str(e), e.stdout.decode()))
            return None, None
        result = fake_cert.decode().split('\n')[:2]
        if not (os.path.isfile(result[0]) and os.path.isfile(result[1])):
            log.error("clone-cert.sh failed")
            return None, None
        return result

    def get_cached_cert(self):
        '''Returns a cached certificate. Result is 'None, None' if it hasn't
        been cached yet'''
        peer = self.get_peer(self.sockets[5])
        # ignore IP, go by server name
        listing = listing = os.listdir('/tmp/')
        cert_filename = None
        for f in listing:
            if f.startswith(self.sni) and f.endswith('_0.cert'):
                cert_filename = os.path.join('/tmp', f)[:-5]
                break
        if not cert_filename:
            return None, None
        key_filename = cert_filename + '.key'
        cert_filename = cert_filename + '.cert'
        if os.path.exists(cert_filename) and os.path.exists(key_filename):
            log.debug("[%s] Get cached certificate for %s" % (self.id, peer))
            return key_filename, cert_filename
        return None, None

    def tlsify_client(self, conn):
        '''Wrap an outgoing connection inside TLS'''
        context = ssl.SSLContext()
        return context.wrap_socket(
            conn,
            do_handshake_on_connect=False,
            server_hostname=self.sni,
        )

    def do_tls_handshake(self, s):
        while True:
            try:
                s.do_handshake()
                break
            except ssl.SSLError as err:
                if err.args[0] == ssl.SSL_ERROR_WANT_READ:
                    select.select([s], [], [])
                elif err.args[0] == ssl.SSL_ERROR_WANT_WRITE:
                    select.select([], [s], [])
                elif err.reason in [
                    "TLSV1_ALERT_UNKNOWN_CA",
                    "SSLV3_ALERT_BAD_CERTIFICATE",
                ]:
                    log.error("[%s] Client does not trust our cert" %
                              self.id)
                    return False
                else:
                    raise
        return True


def _run_steps(steps, netns_name, devname, subnet, ignore_errors=False):
    parameters = {
        "netns": netns_name,
        "devname": devname,
        "subnet": subnet,
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


def _original_dst(conn):
    '''Find original destination of an incoming connection'''
    original_dst = conn.getsockopt(socket.SOL_IP, _SO_ORIGINAL_DST, 16)
    original_srv_port, original_srv_ip = struct.unpack("!2xH4s8x",
                                                       original_dst)
    original_srv_ip = "%d.%d.%d.%d" % (*original_srv_ip,)
    return original_srv_ip, original_srv_port


def _open_connection(ip, port, netns_name=None):
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


class TLSEraser(object):
    def __init__(self,
                 lport,
                 lhost='0.0.0.0',
                 netns_name="mirror",
                 subnet="192.168.253",
                 devname="noTLS",
                 erase_tls=True,
                 forwarder=Forwarder,
                 target=None
                 ):
        self.lport = lport
        self.lhost = lhost
        self.netns_name = netns_name
        self.subnet = subnet
        self.devname = devname
        self.erase_tls = erase_tls
        self.forwarder = forwarder
        if target:
            target = target.split(':')
            self.target = (target[0], int(target[1]))
        else:
            self.target = None

        self._setup_ns = [
            # funny hack
            'ln -fs /proc/1/ns/net /var/run/netns/default',
            # create a test network namespace:
            'true' if self.netns_name == 'default'
            else 'ip netns add %(netns)s',
            # create a pair of virtual network interfaces ($devname-a and
            # $devname):
            'ip link add %(devname)s-a type veth peer name %(devname)s',
            # change the active namespace of the $devname-a interface:
            'ip link set %(devname)s-a netns %(netns)s',
            # configure the IP addresses of the virtual interfaces:
            'ip netns exec %(netns)s ip link set %(devname)s-a up',
            'ip netns exec %(netns)s ip addr add %(subnet)s.1/24 '
            'dev %(devname)s-a',
            'ip link set %(devname)s up',
            'ip addr add %(subnet)s.254/24 dev %(devname)s',
            #  'ip netns exec %(netns)s ip route add default via '
            #  '%(subnet)s.254 dev %(devname)s-a'
        ]

        self._teardown_ns = [
            'ip link del %(devname)s',
            'true' if self.netns_name == 'default'
            else 'ip netns del %(netns)s',
        ]

    def accept(self, sock):
        '''Accept incoming connection (S1) and create the other sockets'''
        global _port_id, _open_ports
        S1, addr = sock.accept()  # Should be ready
        orig_dest = _original_dst(S1)
        if self.target:
            orig_dest = self.target
        log.info('Accepted from %s:%d with target %s:%d' %
                 (*addr, *orig_dest))
        S1.setblocking(False)

        t1 = ThreadWithReturnValue(
            target=self.accept_connection,
            args=(_port_id, self.subnet + '.1', 0, self.netns_name),
            daemon=True,
        )
        _port_id += 1
        t1.start()

        t2 = ThreadWithReturnValue(
            target=self.accept_connection,
            args=(_port_id, self.subnet + '.254', 0, None),
            daemon=True,
        )
        _port_id += 1
        t2.start()

        while True:
            try:
                S2 = _open_connection(*(_open_ports[_port_id-2]))
                break
            except (ConnectionRefusedError, KeyError):
                time.sleep(.05)
        while True:
            try:
                S4 = _open_connection(*(_open_ports[_port_id-1]),
                                      self.netns_name)
                break
            except (ConnectionRefusedError, KeyError):
                time.sleep(.05)

        del _open_ports[_port_id-1]
        del _open_ports[_port_id-2]
        S3 = t1.join()
        S5 = t2.join()
        return self.forwarder([S1, S2, S3, S4, S5],
                              orig_dest,
                              self.erase_tls,
                              )

    def start_data_forwarding(self, sock):
        while True:
            log.debug("Waiting for connection")
            f = self.accept(sock)
            if f:
                f.start()

    def accept_connection(self, port_id, ip, port=0, netns_name=None):
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
        global _open_ports
        _open_ports[port_id] = sock.getsockname()
        sock.listen(2)
        conn, addr = sock.accept()
        log.debug("Accepted from %s:%d" % (*addr,))
        return conn

    def cleanup(self, exc_type=None, exc=None, traceback=None):
        log.info("Cleaning up")
        _run_steps(self._teardown_ns, self.netns_name, self.devname,
                   self.subnet, ignore_errors=True)
        os._exit(0)
        return None

    def run(self):
        atexit.register(self.cleanup)
        signal.signal(signal.SIGTERM, self.cleanup)
        signal.signal(signal.SIGHUP, self.cleanup)

        try:
            # remove possibly existing namespace
            netns.get_ns_path(nsname=self.netns_name)
            _run_steps(self._teardown_ns, self.netns_name,
                       self.devname, self.subnet, ignore_errors=True)
        except Exception:
            pass
        _run_steps(self._setup_ns, self.netns_name, self.devname, self.subnet)
        main_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        main_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        log.info('Start listening for incoming connections on %s:%d...' %
                 (self.lhost, self.lport))
        main_sock.bind((self.lhost, self.lport))
        main_sock.listen(128)

        self.start_data_forwarding(main_sock)
