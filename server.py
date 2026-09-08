#!/usr/bin/env python3
"""CodeLedger MCP server entry point (stdio JSON-RPC).

Register with Claude Code:
    claude mcp add codeledger --scope user -- python3 /data/codeledger/server.py

Env overrides: CODELEDGER_DB (default ~/.codeledger/ledger.db),
CODELEDGER_PROJECT, CODELEDGER_ACTOR.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from codeledger.protocol import serve

if __name__ == "__main__":
    serve()
