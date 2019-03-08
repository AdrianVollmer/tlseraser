#!/usr/bin/env python3

from tlseraser.mitm import main

import logging
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

if __name__ == "__main__":
    main()
