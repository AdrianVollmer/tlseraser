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
    '--mirror',
    default="192.168.253.1:1235",
    dest="MIRROR",
    type=str,
    help="the IP address and the IP address of the pcap mirror "
         "(default: 192.168.253.1:1235)"
)

parser.add_argument(
    '--testing',
    dest="TESTING",
    default=False,
    action='store_true',
    help='for testing purposes only',
)


args = parser.parse_args()

try:
    args.M_LHOST, args.M_LPORT = args.MIRROR.split(":")
    args.M_LPORT = int(args.M_LPORT)
except Exception:
    log.critical("Argument 'mirror' must be of the form <IP>:<PORT>")
    exit(1)
