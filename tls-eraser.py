#!/usr/bin/env python3

from tlseraser.mitm import main, run_steps, teardown_ns

import atexit
import logging
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

atexit.register(run_steps, teardown_ns, True)

if __name__ == "__main__":
    main()
