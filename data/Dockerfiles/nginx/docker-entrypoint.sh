#!/bin/sh

APIHOST=${APIHOST:-"api-mailcow"}
SOGOHOST=${SOGOHOST:-"$IPV4_NETWORK.248"}
RSPAMDHOST=${RSPAMDHOST:-"rspamd-mailcow"}

until ping ${APIHOST} -c1 > /dev/null; do
  echo "Waiting for API..."
  sleep 1
done
if ! printf "%s\n" "${SKIP_SOGO}" | grep -E '^([yY][eE][sS]|[yY])+$' >/dev/null; then
  until ping ${SOGOHOST} -c1 > /dev/null; do
    echo "Waiting for SOGo..."
    sleep 1
  done
fi
if ! printf "%s\n" "${SKIP_RSPAMD}" | grep -E '^([yY][eE][sS]|[yY])+$' >/dev/null; then
  until ping ${RSPAMDHOST} -c1 > /dev/null; do
    echo "Waiting for Rspamd..."
    sleep 1
  done
fi

python3 /bootstrap.py

exec "$@"
