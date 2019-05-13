#!/usr/bin/env python3
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
Inspired by the "Upside Down Internet", which is part of byt3bl33d3r's MITMf
project, this script showcases TLSEraser's API and how to use it if you want
to tamper with the data stream.
"""

from tlseraser.tlseraser import TLSEraser, Forwarder
from tlseraser.args import args
from PIL import Image, ImageFile
from io import BytesIO

import logging

level = logging.getLevelName(logging.DEBUG)
logging.basicConfig(level=level)
log = logging.getLogger(__name__)


image_formats = {
    b'image/jpeg': "JPEG",
    b'image/png': "PNG",
    b'image/gif': "GIF",
}


class Flipper(Forwarder):
    def tamper_in(self, s):
        log.debug('Tampering with buffer')
        try:
            data = self.buffer[s]
            header = data.split(b'\x0d\x0a\x0d\x0a')[0]
            header = header.split(b'\x0d\x0a')
            header = {x.split(b':')[0]: b':'.join(x.split(b': ')[1:])
                      for x in header}
            body = data.split(b'\x0d\x0a\x0d\x0a')[1]
            con_length = int(header[b'Content-Length'])
            if len(body) < con_length:
                # request is not finished yet
                log.debug('request not finished')
                return False
        except Exception:
            # looks like it's not http
            log.debug('Was not an HTTP request')
            return True

        try:
            if header[b'Content-Type'] in image_formats.keys():
                p = ImageFile.Parser()
                p.feed(body)
                im = p.close()
                im = im.transpose(Image.ROTATE_180)
                output = BytesIO()
                im.save(output, format=image_formats[header[b'Content-Type']])
                body = output.getvalue()
                output.close()
            else:
                log.debug('unknown mime-type')
                return True
            header[b'Content-Length'] = str(len(body)).encode()
            result = b''
            for k, v in header.items():
                result += k + b": " + v + b'\x0d\x0a'
            result += b'\x0d\x0a' + body
            self.buffer[s] = result
            log.info('Image flipped')
            return True
        except Exception:
            log.debug('Was not an image')
            return True


try:
    TLSEraser(
        args.LPORT,
        lhost=args.LHOST,
        netns_name=args.NETNS_NAME,
        forwarder=Flipper,
    ).run()
except KeyboardInterrupt:
    print('\r', end='')  # prevent '^C' on console
    print('Caught Ctrl-C, exiting...')
