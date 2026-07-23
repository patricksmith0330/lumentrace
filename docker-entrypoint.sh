#!/bin/sh
set -eu

if [ "$(id -u)" = "0" ]; then
  mkdir -p "${DATA_DIR:-/data}"
  chown -R lumentrace:lumentrace "${DATA_DIR:-/data}"
  exec gosu lumentrace /bin/sh "$0" "$@"
fi

python manage.py migrate --noinput
python manage.py migrate_flask_auth

exec env START_MONITORING=1 \
  waitress-serve \
  --listen=0.0.0.0:5000 \
  --threads=10 \
  lumentrace.wsgi:application
