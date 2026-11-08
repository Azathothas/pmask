#!/bin/sh
# How pmask compares with zapper and memexec, measured.
#
# zapper is built from source and run against a passive payload, so every
# column below is what an observer reads from /proc while the payload is
# alive.  The payload prints its own argv once, which is the other half:
# a redaction that also breaks the program is not a result.
#
# memexec is not a launcher in the same class.  It exists to execute a
# binary from a noexec mount by writing it to a memfd, so the only column
# it shares is "what does /proc/<pid>/exe name".  That column is shown for
# pmask --rexec, which does the same thing for a different reason.
#
# Usage: sh measurements/vs-zapper.sh [path-to-built-zapper]
#   With no argument it clones and builds zapper under $TMPDIR.
#   Every case prints PASS, SKIP or a ROW line; the script exits 0 as long
#   as it produced the table.
set -u
cd "$(dirname "$0")" || exit 2
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOL="${PMASK_BIN:-$ROOT/target/release/pmask}"
[ -x "$TOOL" ] || { echo "FATAL: $TOOL missing (cargo build --release --bin pmask)"; exit 2; }

T="${TMPDIR:-/tmp}/pmask-vs-zapper.$$"
mkdir -p "$T"
chmod 700 "$T"
trap 'rm -rf "$T"' EXIT INT TERM

# ---------------------------------------------------------------- payload
# A passive target: it prints argv once and holds.  It never touches its
# own /proc window, so the row describes the launcher and nothing else.
cat > "$T/target.c" <<'C'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
    FILE *o = fopen(argv[2], "w");
    if (!o) return 1;
    fprintf(o, "argc=%d", argc);
    for (int i = 0; i < argc; i++) fprintf(o, " argv[%d]=[%s]", i, argv[i]);
    fputc('\n', o);
    fclose(o);
    sleep(argc > 3 ? atoi(argv[3]) : 6);
    return 0;
}
C
if ! cc -O1 -o "$T/target" "$T/target.c" 2>/dev/null; then
    echo "SKIP vs-zapper: no C compiler to build the probe payload"
    exit 0
fi

# ------------------------------------------------------------------ zapper
ZAPPER="${1:-}"
if [ -z "$ZAPPER" ]; then
    if command -v git >/dev/null 2>&1 && command -v cc >/dev/null 2>&1; then
        if git clone -q --depth 1 https://github.com/hackerschoice/zapper.git \
            "$T/zapper" 2>/dev/null && (cd "$T/zapper" && make >/dev/null 2>&1); then
            ZAPPER="$T/zapper/zapper"
        fi
    fi
fi
if [ -n "$ZAPPER" ] && [ -x "$ZAPPER" ]; then
    ZAPVER=$("$ZAPPER" -h 2>&1 | sed -n 's/^Version \([^ ]*\).*/\1/p' | head -1)
    echo "zapper: $ZAPPER (version ${ZAPVER:-unknown})"
else
    echo "SKIP vs-zapper: zapper not built, the rows that need it are marked"
    ZAPPER=""
fi

# The host conditions every number below carries.
echo "host: $(uname -srm) uid=$(id -u) CapEff=$(sed -n 's/^CapEff:[[:space:]]*//p' /proc/self/status)"
echo

# --------------------------------------------------------------- the table
# One row per launcher.  Columns are read from /proc for the live payload.
row() {
    rw_label="$1"
    shift
    rw_can="VSZAP-$rw_label-$$"
    rw_out="$T/$rw_label.out"
    rm -f "$rw_out"
    if [ "$#" -gt 0 ]; then
        "$@" "$T/target" "$rw_can" "$rw_out" 6 >/dev/null 2>&1 &
    else
        "$T/target" "$rw_can" "$rw_out" 6 >/dev/null 2>&1 &
    fi
    rw_l=$!
    rw_i=0
    while [ "$rw_i" -lt 50 ]; do
        [ -s "$rw_out" ] && break
        sleep 0.1
        rw_i=$((rw_i + 1))
    done
    rw_p=""
    for d in /proc/[0-9]*; do
        pid=${d#/proc/}
        [ "$pid" = "$$" ] && continue
        case "$(readlink "$d/exe" 2>/dev/null)" in
            */target) rw_p=$pid ;;
        esac
    done
    if [ -z "$rw_p" ]; then
        echo "ROW $rw_label: payload not found"
        kill -9 "$rw_l" 2>/dev/null
        return 0
    fi
    rw_comm=$(cat "/proc/$rw_p/comm" 2>/dev/null)
    rw_tracer=$(sed -n 's/^TracerPid:[[:space:]]*//p' "/proc/$rw_p/status" 2>/dev/null)
    rw_cmdbytes=$(wc -c < "/proc/$rw_p/cmdline" 2>/dev/null | tr -d ' ')
    rw_span=$(awk '{ print $49 - $48 }' "/proc/$rw_p/stat" 2>/dev/null)
    rw_nuls=$(tr -cd '\0' < "/proc/$rw_p/cmdline" 2>/dev/null | wc -c | tr -d ' ')
    rw_envbytes=$(wc -c < "/proc/$rw_p/environ" 2>/dev/null | tr -d ' ')
    rw_cancmd=$(tr '\0' '\n' < "/proc/$rw_p/cmdline" 2>/dev/null | grep -cF "$rw_can" | tr -d ' ')
    rw_canenv=$(tr '\0' '\n' < "/proc/$rw_p/environ" 2>/dev/null | grep -cF "$rw_can" | tr -d ' ')
    printf 'ROW %-9s comm=%-10s tracer=%-6s cmd=%-4s span=%-4s nul=%-3s env=%-5s canary_cmd=%s canary_env=%s argv=%s\n' \
        "$rw_label" "$rw_comm" "$rw_tracer" "$rw_cmdbytes" "$rw_span" "$rw_nuls" \
        "$rw_envbytes" "$rw_cancmd" "$rw_canenv" \
        "$(head -1 "$rw_out" 2>/dev/null | cut -c1-40)"
    kill -9 "$rw_l" 2>/dev/null
    kill -9 "$rw_p" 2>/dev/null
}

row control
if [ -n "$ZAPPER" ]; then
    row zapper "$ZAPPER"
    row zapper-f "$ZAPPER" -f
    row zapper-a "$ZAPPER" -a worker
    row zapper-fa "$ZAPPER" -f -a worker
fi
row pmask "$TOOL" --label ci-runner --
row pmask-detach "$TOOL" --label ci-runner --detach --

echo
echo "columns, and what a difference in each one means:"
echo "  comm      /proc/pid/comm.  pmask writes the label; zapper leaves the binary name."
echo "  tracer    TracerPid.  Non-zero means a supervisor is attached for the payload's life."
echo "            zapper detaches after the exec; zapper -f stays attached to follow children."
echo "  cmd       byte length of /proc/pid/cmdline, and span is fields 49 minus 48 of"
echo "            /proc/pid/stat.  They should agree.  zapper leaves the original extent and"
echo "            fills it with NULs, so both stay large and the NUL count is not 1."
echo "  env       byte length of /proc/pid/environ.  zapper zeroes the strings but keeps the"
echo "            window, so the length stays; pmask moves the window, so it reads 0."
echo "  canary    whether the payload's own secret argument or variable is still readable."
echo "  argv      what the payload itself received.  It must be unchanged in every row: a"
echo "            redaction that alters argv is a broken program, not a stronger redaction."
echo
echo "exe names, with and without --rexec:"
REX="$T/rexec.out"
"$TOOL" --label ci-runner --rexec -- /bin/sleep 2 >/dev/null 2>&1 &
rl=$!
sleep 0.8
for d in /proc/[0-9]*; do
    [ "$(cat "$d/comm" 2>/dev/null)" = "ci-runner" ] || continue
    case "$(readlink "$d/exe" 2>/dev/null)" in
        /memfd:*) echo "  --rexec   pid=${d#/proc/} exe=$(readlink "$d/exe" 2>/dev/null)" ;;
    esac
done
kill -9 "$rl" 2>/dev/null
"$TOOL" --label ci-runner -- /bin/sleep 2 >/dev/null 2>&1 &
rl=$!
sleep 0.8
for d in /proc/[0-9]*; do
    [ "$(cat "$d/comm" 2>/dev/null)" = "ci-runner" ] || continue
    case "$(readlink "$d/exe" 2>/dev/null)" in
        /memfd:*) ;;
        *) echo "  no --rexec pid=${d#/proc/} exe=$(readlink "$d/exe" 2>/dev/null)" ;;
    esac
done
kill -9 "$rl" 2>/dev/null
rm -f "$REX"

echo
echo "memexec is a different tool: it writes a binary to a memfd and execs"
echo "it through execveat, so that a noexec mount cannot refuse the exec."
echo "It redacts nothing and hides nothing.  The one property it shares with"
echo "pmask --rexec is that /proc/<pid>/exe names a memfd rather than the"
echo "file, and the row above is that property measured."
echo
echo "VS-ZAPPER: OK"
