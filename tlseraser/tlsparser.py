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
This module is needed to extract the SNI from a client hello.
"""


def get_sni(tls_record):
    result = parse(tls_record_struct, tls_record)
    result = result['content']['extensions']['extension_type']
    result = result['sni']['server_name']['data'].decode()
    return result


def parse(struct, data):
    if not data:
        return None
    result = {}
    if not isinstance(struct[0], list):
        struct = [struct]
    for p in struct:
        if len(p) == 1:
            return {'length': len(data), 'data': data}
        elif len(p) == 2:
            result[p[1]] = data[:p[0]]
            data = data[p[0]:]
        elif len(p) == 3:
            if isinstance(p[2], list):
                length = int.from_bytes(data[:p[0]], "big")
                result[p[1]] = parse(p[2], data[p[0]:p[0]+length])
                data = data[p[0]+length:]
            elif isinstance(p[2], str):
                length = int.from_bytes(data[:p[0]], "big")
                result[p[2]] = data[p[0]:p[0]+length]
                data = data[p[0]+length:]
            elif isinstance(p[2], dict):
                type = data[:p[0]]
                result[p[1]] = parse(p[2][type], data[p[0]:])
                data = data[p[0]+len(result[p[1]]):]
            elif isinstance(p[2], int):
                length = int.from_bytes(data[:p[0]], "big")
                result[p[1]] = []
                for i in range(length // p[2]):
                    result[p[1]].append(data[p[0] + i * p[2]:
                                             p[0] + (i+1) * p[2]])
                data = data[p[0] + length:]
            else:
                raise Exception
        else:
            raise Exception
    return result


tls_record_struct = [
    [1, "content_type"],
    [2, "version"],
    [2, "content", [
        [1, "handshake_type"],
        [3, "length"],
        [2, "version"],
        [32, "random"],
        [1, "session_id", ["session_id"]],
        [2, "cipher_suites", 2],
        [1, "compression_methods", 1],
        [2, "extensions",
            [2, "extension_type", {
                b"\x00\x00": [  # sni
                    [2, "length"],
                    [2, "sni", [
                        [1, "name_type"],
                        [2, "server_name", ["server_name"]],
                    ]],
                ],
                b"\x00\x0d": [  # signing algorithm
                    [2, "length"],
                    [2, "data", ["data"]]
                ],
                b"\x00\x0f": [  # heart beat
                    [2, "length"],
                    [2, "data", ["data"]]
                ],
            }],
         ],
    ]],
]


#  class BinList(object):
#  class BinConst(object)

def test(data):
    import hexdump
    hexdump.hexdump(data)
    print(parse(tls_record_struct, data))
