#!/usr/bin/env sh
set -eu

if [ -z "${FREE5GC_REF:-}" ]; then
  printf '%s\n' 'Set FREE5GC_REF to an upstream tag or commit, for example: FREE5GC_REF=<ref> make bootstrap' >&2
  exit 2
fi

python3 -m free5gc_security_lab bootstrap --ref "$FREE5GC_REF"
