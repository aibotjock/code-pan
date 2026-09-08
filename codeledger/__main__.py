import os
import sys

if __package__ in (None, ""):  # executed as a plain script
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from codeledger.protocol import serve
else:
    from .protocol import serve

if __name__ == "__main__":
    serve()
