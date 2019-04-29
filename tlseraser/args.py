import argparse
import logging
log = logging.getLogger(__name__)

parser = argparse.ArgumentParser(
    description="Terminate TLS encrpytion and mirror the clear text traffic "
                "on another device"
)

parser.add_argument(
    '-p',
    '--lport',
    default=1234,
    dest="LPORT",
    type=int,
    help="the local port to listen on (default: 1234)"
)

parser.add_argument(
    '-l',
    '--lhost',
    default="0.0.0.0",
    dest="LHOST",
    type=str,
    help="the IP address to listen on (default: 0.0.0.0)"
)

parser.add_argument(
    '-m',
    '--mirror-subnet',
    default="192.168.253",
    dest="MIRROR_SUBNET",
    type=str,
    help="the IP subnet of the pcap mirror (default: %(default)s)"
)

parser.add_argument(
    '--testing',
    dest="TESTING",
    default=False,
    action='store_true',
    help='for testing purposes only',
)


args = parser.parse_args()
