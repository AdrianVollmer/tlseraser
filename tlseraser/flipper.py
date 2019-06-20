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

from tlseraser.tlseraser import Forwarder
from PIL import Image, ImageFile
from io import BytesIO
import re

import logging
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
            try:
                header, body = data.split(b'\x0d\x0a\x0d\x0a')[:2]
            except ValueError:
                return True
            con_length = re.search(b'Content-Length: ([0-9]+)\x0d\x0a',
                                   header,
                                   re.IGNORECASE)
            con_length = int(con_length.group(1)) if con_length else 0
            if len(body) < con_length:
                # request is not finished yet
                log.debug('request not finished')
                return False
        except Exception:
            # looks like it's not http
            #  log.debug('Was not an HTTP request')
            log.exception('exception')
            return True

        try:
            con_type = re.search(b'Content-Type: ([^\x0d\x0a;]+)\x0d\x0a',
                                 header,
                                 re.IGNORECASE)
            con_type = con_type.group(1) if con_type else None

            if con_type in image_formats.keys():
                p = ImageFile.Parser()
                p.feed(body)
                im = p.close()
                im = im.transpose(Image.ROTATE_180)
                output = BytesIO()
                im.save(output, format=image_formats[con_type])
                body = output.getvalue()
                output.close()
            else:
                log.debug('unknown mime-type')
                return True
            header = re.sub(b'Content-Length: [0-9]+\x0d\x0a',
                            b'Content-Length: %d\x0d\x0a' % len(body),
                            header)
            result = header + b'\x0d\x0a\x0d\x0a' + body
            self.buffer[s] = result
            log.info('Image flipped')
            return True
        except Exception:
            log.exception('Was not an image')
            return True
