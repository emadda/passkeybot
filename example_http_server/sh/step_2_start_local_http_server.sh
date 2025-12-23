#!/usr/bin/env bash
set -euo pipefail

# Start a local Bun HTTP server.
bun --console-depth 10 --hot src/http_server.ts