#!/bin/sh
# Runs inside a fresh verification container (docker run --network none).
# Inputs, mounted read-only at /threadscan/in:
#   reproducer.sh   the candidate's script
#   files/          the candidate's extra files, laid out relative to the workdir
#   patch.diff      the candidate's patch (patched mode only)
# Environment: THREADSCAN_MODE (unpatched|patched), THREADSCAN_WORKDIR, THREADSCAN_NONCE.
# Exit 97 + marker line = the patch did not apply. Any other exit is the reproducer's.
set -u

cd "${THREADSCAN_WORKDIR:?}" || { echo "threadscan: workdir ${THREADSCAN_WORKDIR} missing" >&2; exit 98; }

if [ -d /threadscan/in/files ]; then
    cp -R /threadscan/in/files/. . || { echo "threadscan: could not write reproducer files" >&2; exit 98; }
fi

if [ "${THREADSCAN_MODE:-}" = "patched" ]; then
    if ! git apply --whitespace=nowarn /threadscan/in/patch.diff 2>/tmp/threadscan-apply.err; then
        if ! patch -p1 --forward --batch </threadscan/in/patch.diff >>/tmp/threadscan-apply.err 2>&1; then
            echo "THREADSCAN-PATCH-FAILED"
            cat /tmp/threadscan-apply.err >&2
            exit 97
        fi
    fi
fi

exec bash /threadscan/in/reproducer.sh
