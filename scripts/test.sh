#!/usr/bin/env bash
# Canonical green-check. pipefail matters: `python3 -m unittest … | tail` alone
# masks the exit code and a red suite reads as green.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m unittest discover -s tests -v 2>&1 | tail -25
