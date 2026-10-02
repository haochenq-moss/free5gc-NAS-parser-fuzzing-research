#!/usr/bin/env bash

LAB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FREE5GC_ROOT="$LAB_ROOT/vendor/free5gc"

if [[ ! -f "$FREE5GC_ROOT/quick-setup.sh" ]]; then
    printf 'free5GC checkout is missing: %s\n' "$FREE5GC_ROOT" >&2
    return 1 2>/dev/null || exit 1
fi

(
    cd "$FREE5GC_ROOT"
    source ./quick-setup.sh "$@"
)