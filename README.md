TLSEraser
=========

TLSEraser allows you to eavesdrop on TCP connections secured by TLS. It
creates a new virtual interface with the clear text, which you can read
easily using libpcap, i. e. with tcpdump or wireshark.

It does this by performing the TLS handshake both torwards the incoming
connection and towards its original destination. In between, the TCP stream
is forwarded in clear text to an IP address in a different network
namespace, which I call a mirror. This is necessary so libpcap can see the
packets. Here is a figure illustrating the mechanism:

```
               S1  S2            S5  S6
source ---->----o  o              o  o---->---- original destination
                    \            /
                     \          /                        namespace 1
====================================================================
                       \      /                          namespace 2
                        \    /
                         o  o
                        S3  S4
```

The sockets are labeled from S1 to S6. The TLS connection is terminated at
S1 and re-established at S6. Everytime a connection is accepted at S1, a
TLSEraser object is spawned in its own thread which creates the other
sockets and forwards the data correspondingly. It also automatically detects
a TLS handshake at S1 and will perform it using a forged certificate using
`clone-cert.sh`. On the other end, at S6, it will perform the TLS handshake
at the same time.

Installation
------------

You can just run `./example.py` without installing TLSEraser, but if you
want to install it to your system, read on.

### From Github

```
git clone https://github.com/AdrianVollmer/tlseraser.git
cd tlseraser
python3 setup.py install  # as root
python3 setup.py install  --user  # as a regular user (recommended)
```

If you install it as a regular user, make sure that `$HOME/.local/bin` is
part of your `$PATH` variable.

### Via pip

```
pip3 install tlseraser  # as root
pip3 install --user tlseraser  # as a regular user (recommended)
```

If you install it as a regular user, make sure that `$HOME/.local/bin` is
part of your `$PATH` variable.

Dependencies
------------

* [python-netns](https://github.com/larsks/python-netns)
* `iproute2` (should be installed on all modern Linux distributions)
* `clone-cert.sh` (included)

Usage
-----

```
usage: example.py [-h] [-p LPORT] [-l LHOST] [-m MIRROR_SUBNET] [-t TARGET]
                  [--log-level {CRITICAL,ERROR,WARNING,INFO,DEBUG}]

Terminate TLS encrpytion and mirror the clear text traffic on another device

optional arguments:
  -h, --help            show this help message and exit
  -p LPORT, --lport LPORT
                        the local port to listen on (default: 1234)
  -l LHOST, --lhost LHOST
                        the IP address to listen on (default: 0.0.0.0)
  -m MIRROR_SUBNET, --mirror-subnet MIRROR_SUBNET
                        the IP subnet of the pcap mirror (default:
                        192.168.253)
  -t TARGET, --target TARGET
                        the target service as <HOST>:<IP>; if none is given
                        (the default), the original destination of NATed TCP
                        packets is determined via SO_ORIGINAL_DST
  --log-level {CRITICAL,ERROR,WARNING,INFO,DEBUG}
                        the logging level (default: INFO)
```

Example
-------

### Single target

Run `tlseraser --target example.com:443`. Start Wireshark on the interface
`noTLS`. Now connect to https://localhost:1234 with a brower (obviously you
will get a certificate warning) and watch the clear text traffic in
Wireshark.

### Arbitrary target

First, create a rule with `iptables` that redirects all traffic you want to
eavesdrop on to port 1234 on localhost. Then run `tlseraser`.

### Intercepting local traffic

If you want to intercept traffic originating from your own machine, it's
best to use `iptables` owner match. Create a new group, say 'tlseraser, with
`addgroup tlseraser` and add your user to that group: `adduser <username> tlseraser`.
Next, create an `iptables` rules such as this:

```
iptables -t nat -A OUTPUT -p tcp -m owner --gid-owner tlseraser -j DNAT --to 127.0.0.1:1234
```

Now change your GID with `sg tlseraser`, make sure everything is right with
`id`, start TLSEraser and run the process you want to examine.


### Intercepting forwarded traffic

Assuming you already obtained a Man-in-the-Middle position, simply create an
`iptables` rules like this:

```
iptables -t nat -A PREROUTING -p tcp <matching rules> -j DNAT --to-destination 127.0.0.1:1234
```
