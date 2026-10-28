#!/usr/bin/env bash
# e2e stage of the fleet standard: start the compose stack, run the stack test, write its
# result as JUnit XML (e2e-junit.xml, one test case per check) and stop the stack.
# Used by ci.yml (e2e on dispatch) and promote.yml (e2e before stg).
#
# Usage: tests/stack/e2e.sh   (exit code = exit code of the stack test; 1 when it printed no
# "ok" or "FAIL" line, the output format of stack_test.sh)
set -euo pipefail
cd "$(dirname "$0")/../.."

log=$(mktemp)
trap 'rm -f "$log"; docker compose down --volumes >/dev/null 2>&1 || true' EXIT

scripts/init-env.sh
# llm trusts the local test issuer and answers with the fake provider (synthwerk#32).
tests/stack/issuer.sh setup
docker compose up --build --wait --wait-timeout 300

# PIPESTATUS keeps the exit code of the stack test itself, not the one of tee.
set +e
tests/stack/stack_test.sh | tee "$log"
status=${PIPESTATUS[0]}
set -e

# xml_escape <text>: escape the five XML special characters.
xml_escape() {
  local s=$1
  # Quoted replacements: bash 5.2 reads a bare & in the replacement as the match.
  s=${s//&/'&amp;'}
  s=${s//</'&lt;'}
  s=${s//>/'&gt;'}
  s=${s//\"/'&quot;'}
  s=${s//\'/"&apos;"}
  printf '%s' "$s"
}

total=0
failed=0
cases=""
while IFS= read -r line; do
  case "$line" in
    "ok   "*) name=${line#ok   } ;;
    "FAIL "*) name=${line#FAIL } ;;
    *) continue ;;
  esac
  total=$((total + 1))
  name=$(xml_escape "$name")
  if [[ "$line" == "FAIL "* ]]; then
    failed=$((failed + 1))
    cases+="    <testcase classname=\"stack\" name=\"$name\"><failure message=\"check failed\"/></testcase>"$'\n'
  else
    cases+="    <testcase classname=\"stack\" name=\"$name\"/>"$'\n'
  fi
done <"$log"

# No check line means the stack test did not run its checks: report that as a failure.
if ((total == 0)); then
  total=1
  failed=1
  cases="    <testcase classname=\"stack\" name=\"stack test output\"><failure message=\"no ok or FAIL line\"/></testcase>"$'\n'
  ((status != 0)) || status=1
fi

{
  printf '<?xml version="1.0" encoding="UTF-8"?>\n'
  printf '<testsuites>\n  <testsuite name="stack" tests="%d" failures="%d">\n' "$total" "$failed"
  printf '%s' "$cases"
  printf '  </testsuite>\n</testsuites>\n'
} >e2e-junit.xml

# A FAIL line fails the run, also when the stack test itself exited 0.
((failed == 0)) || ((status != 0)) || status=1

if ((status != 0)); then
  docker compose logs --no-color --tail 200
fi
exit "$status"
