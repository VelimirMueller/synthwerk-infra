#!/usr/bin/env bash
# Push host and vision health to the Gatus watcher (status.velimir-mueller.de).
# Env from /etc/synthwerk/heartbeat.env: GATUS_URL, HB_TOKEN_HOST, HB_TOKEN_VISION.
# Error texts show on the public status page: keep them short and free of hosts or IPs.
set -uo pipefail

# Gatus wants a POST with the values in the query string: -G puts them there, -X POST keeps the method.
push() { # key token success error duration
  curl -fsS -m 10 -o /dev/null -X POST -G \
    -H "Authorization: Bearer $2" \
    --data-urlencode "success=$3" --data-urlencode "error=$4" --data-urlencode "duration=$5" \
    "$GATUS_URL/api/v1/endpoints/$1/external" || echo "push $1 failed" >&2
}

# host: alive, root disk below 85 %
disk=$(df --output=pcent / | tail -1 | tr -dc '0-9')
if [[ ! "$disk" =~ ^[0-9]+$ ]]; then push synthwerk-dev_host "$HB_TOKEN_HOST" false "disk unknown" 0s
elif (( disk < 85 )); then push synthwerk-dev_host "$HB_TOKEN_HOST" true "" 0s
else push synthwerk-dev_host "$HB_TOKEN_HOST" false "disk ${disk}%" 0s; fi

# vision: /readyz from inside, the app is bound to loopback
start=$(date +%s%N)
body=$(curl -fsS -m 5 http://127.0.0.1:8001/readyz 2>/dev/null)
ms=$(( ($(date +%s%N) - start) / 1000000 ))
if [[ "$body" == '{"status":"ok"'* ]]; then push synthwerk-dev_vision "$HB_TOKEN_VISION" true "" "${ms}ms"
else push synthwerk-dev_vision "$HB_TOKEN_VISION" false "readyz not ok" "${ms}ms"; fi
