#!/bin/sh
# Runs inside a fresh verification container (docker run --network none).
# Inputs, mounted read-only at /vulnscan/in:
#   reproducer.sh   the candidate's script
#   files/          the candidate's extra files, laid out relative to the workdir
#   patch.diff      the candidate's patch (patched mode only)
# Environment: VULNSCAN_MODE (unpatched|patched), VULNSCAN_WORKDIR, VULNSCAN_NONCE.
# Exit 97 + marker line = the patch did not apply. Any other exit is the reproducer's.
set -u

cd "${VULNSCAN_WORKDIR:?}" || { echo "vulnscan: workdir ${VULNSCAN_WORKDIR} missing" >&2; exit 98; }

if [ -d /vulnscan/in/files ]; then
    cp -R /vulnscan/in/files/. . || { echo "vulnscan: could not write reproducer files" >&2; exit 98; }
fi

if [ "${VULNSCAN_MODE:-}" = "patched" ]; then
    if ! git apply --whitespace=nowarn /vulnscan/in/patch.diff 2>/tmp/vulnscan-apply.err; then
        if ! patch -p1 --forward --batch </vulnscan/in/patch.diff >>/tmp/vulnscan-apply.err 2>&1; then
            echo "VULNSCAN-PATCH-FAILED"
            cat /tmp/vulnscan-apply.err >&2
            exit 97
        fi
    fi
fi

exec bash /vulnscan/in/reproducer.sh
