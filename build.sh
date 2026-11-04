#!/bin/bash
set -euo pipefail
root=$(cd "$(dirname "$0")" && pwd)
exec make -C "$root" build-all "$@"
