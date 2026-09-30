#!/bin/bash
set -e

# The database schema is created/upgraded by the API on start-up (mailcow.dbinit).
# Doing it in a separate process keeps the check for the watchdog simple.
if [[ "${MASTER}" =~ ^([yY][eE][sS]|[yY])+$ ]] || [[ -z "${MASTER}" ]]; then
  python -m mailcow.dbinit
fi

# Run as unprivileged user; files that must be writable are chowned by compose volume mounts
exec "$@"
