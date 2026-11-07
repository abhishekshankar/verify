#!/bin/sh
# Build the hosted image, start it with SQLite and a throwaway export key, and check the API answers.
# Run from verify/. Needs Docker. Cleans up its container on exit.
set -eu
IMG=verify-hosted:smoke NAME=verify-smoke-$$ PORT=${PORT:-18080}
docker build -q -f hosted/Dockerfile -t "$IMG" . >/dev/null
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
docker run -d --name "$NAME" -p "127.0.0.1:$PORT:8080" \
  -e VERIFY_EXPORT_KEY=smoke-only -e VERIFY_DATABASE_URL=sqlite:////tmp/smoke.db "$IMG" >/dev/null
for i in $(seq 1 30); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/v1/verify-chain" || true)
  [ "$code" = 401 ] && break; sleep 1
done
[ "$code" = 401 ] || { docker logs "$NAME"; echo "expected 401 from unauthenticated probe, got ${code:-none}"; exit 1; }
KEY=$(docker exec "$NAME" python -m hosted.server add-tenant smoke)
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $KEY" "http://127.0.0.1:$PORT/v1/verify-chain")
[ "$code" = 200 ] || { echo "expected 200 with a tenant key, got $code"; exit 1; }
[ "$(docker exec "$NAME" id -u)" = 10001 ] || { echo "container must run as non-root uid 10001"; exit 1; }
echo "docker smoke: ok (401 without key, 200 with key, non-root)"
