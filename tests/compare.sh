#!/bin/sh
# ============================================================================
# pmask compare suite: one measurement row per presentation variant.
#
# This is a measurement with a few asserted rows.  Each row records what
# /proc shows for the live payload of one variant, so two hosts, two kernels
# or two revisions can be compared field by field.  A value that cannot be
# measured is SKIP with the reason printed in the human table.  A value is
# never guessed and a skipped column never turns into a zero.
#
#   control          /bin/sh -c 'sleep N' CANARY, with PMK_COMPARE_CANARY set
#                    in the environment
#   redacted         pmask run --label ci-runner -- /bin/sh -c ... CANARY
#   redacted-nodumpable  the same job with --no-dumpable
#   redacted-detach  the same job with a detach flag, only when the binary
#                    advertises one, otherwise the row is marked SKIP
#
# The SUPERVISOR lines carry the holder's own maps readability: the
# supervisor is non-dumpable for the session, and --no-dumpable extends
# the treatment to the payload.
#
# Machine format: a header line starting with FIELDS, then one ROW line per
# variant.  Fields are separated by one space, so an awk script can read the
# table without knowing the column order:
#
#   awk '$1 == "ROW" { print $2, $9, $12 }'
#
# A field that would contain a space (a maps line, an exe path) uses '|' in
# place of the space, so a record is always one line.  The human table at the
# end prints the same values with the separators restored.
#
# Exit: 0 when the table was produced and the asserted rows pass (DETACH-TREE,
# AUDIT, MAP_FILES, and the supervisor maps on a non-root host); 1 when one of
# those rows fails; 2 when the binaries are missing and cannot be built.
# ============================================================================
set -u
cd "$(dirname "$0")"
. ./lib.sh

# The task is a measurement of whatever binary is in tests/, so build only
# when it is absent, the way refresh_bins does.  A stale binary is reported
# but does not stop the run: the numbers are still a measurement, they just
# describe the older build.
ensure_tool() {
    et_root="$BIN_DIR/.."
    if [ ! -x "$TOOL" ]; then
        command -v cargo >/dev/null 2>&1 || {
            echo "COMPARE: FAIL $TOOL is missing and cargo is not installed" >&2
            return 1
        }
        [ -f "$et_root/Cargo.toml" ] || {
            echo "COMPARE: FAIL $TOOL is missing and $et_root/Cargo.toml is not there" >&2
            return 1
        }
        ( cd "$et_root" && cargo build --release --bins ) || {
            echo "COMPARE: FAIL cargo build --release --bins failed" >&2
            return 1
        }
        cp -p "$et_root/target/release/pmask" "$TOOL" || {
            echo "COMPARE: FAIL cannot install $TOOL from target/release" >&2
            return 1
        }
    fi
    et_newer=$(find "$et_root/src" -name '*.rs' -newer "$TOOL" 2>/dev/null | head -1)
    if [ -n "$et_newer" ]; then
        printf 'note: %s is older than %s, so these numbers describe the older build\n' \
            "$TOOL" "$et_newer"
    fi
    return 0
}

ensure_tool || exit 2

T=/tmp/pmask-compare.$$
mkdir -p "$T" || { echo "COMPARE: FAIL cannot create $T" >&2; exit 2; }

SUP=""
PAYLOAD=""
cleanup() {
    # Every process this script started, and only those.  kill_comm is
    # scoped to processes that descend from this shell, so the label match
    # cannot reach a session somebody else is running.
    [ -n "$PAYLOAD" ] && kill -9 "$PAYLOAD" 2>/dev/null
    [ -n "$SUP" ] && kill -9 "$SUP" 2>/dev/null
    kill_comm "$LABEL" KILL 2>/dev/null
    kill_comm sleep KILL 2>/dev/null
    kill_comm testcases KILL 2>/dev/null
    rm -rf "$T"
    :
}
trap cleanup EXIT INT TERM

LABEL='ci-runner'
CAN="PMKCAN-$(fresh_marker)"
[ -n "$CAN" ] || CAN="PMKCAN-fallback-$$"
ENVNAME=PMK_COMPARE_CANARY
# Payload lifetime.  Long enough to read fifteen columns without racing the
# exit, short enough that three variants stay inside a few seconds.
HOLD=3

# ---------------------------------------------------------------- helpers

# stat_fields PID -> "arg_start arg_end env_start env_end" in decimal, the
# /proc/<pid>/stat fields 48 to 51.  comm may hold spaces and parentheses, so
# the parse starts after the last ')' and the first token there is field 3.
stat_fields() {
    sed 's/^.*) //' "/proc/$1/stat" 2>/dev/null | awk '{ print $46, $47, $48, $49 }'
}

# bytes PATH -> size in bytes, or SKIP when the file cannot be read.  The
# subshell carries the redirect so a refused /proc file prints nothing.
bytes() {
    b_out=$( ( wc -c < "$1" ) 2>/dev/null | tr -d ' ' )
    if [ -n "$b_out" ]; then
        printf '%s' "$b_out"
    else
        printf 'SKIP'
    fi
}

# maps_bytes PID -> bytes of /proc/<pid>/maps, or REFUSED when a
# same-uid reader is denied.  The supervisor holds the real argv of every
# tracee, so this column is its own disclosure surface.
maps_bytes() {
    mb=$( ( wc -c < "/proc/$1/maps" ) 2>/dev/null | tr -d ' ' )
    if [ -n "$mb" ]; then printf '%s' "$mb"; else printf 'REFUSED'; fi
}

# has PATH NEEDLE -> 1 when PATH holds NEEDLE, 0 when not, SKIP when the
# file cannot be read.  The file is binary, so NUL becomes a newline first.
# `grep -F` is dropped deliberately: busybox grep 1.37 with -F matches only
# the text before the first NUL, so the fixed-string path misses a needle
# that starts after one.  The readability test comes first, because an
# unreadable file and a file without the needle both make grep exit 1 and
# the two must not be reported as the same answer.
has() {
    if ! ( : < "$1" ) 2>/dev/null; then
        printf 'SKIP'
        return 0
    fi
    ( tr '\0\n' '\n\n' < "$1" | grep -q -- "$2" ) 2>/dev/null
    case $? in
        0) printf '1' ;;
        1) printf '0' ;;
        *) printf 'SKIP' ;;
    esac
}

# nul_count PATH
nul_count() {
    n_out=$( ( tr -cd '\0' < "$1" | wc -c ) 2>/dev/null | tr -d ' ' )
    if [ -n "$n_out" ]; then
        printf '%s' "$n_out"
    else
        printf 'SKIP'
    fi
}

# nul_run PATH -> the longest run of consecutive NUL bytes.  MITRE ATT&CK
# T1036.011 names NUL runs in cmdline as the detection signal, so the length
# of the run is the number that matters.
nul_run() {
    if [ "$HAVE_OD" = 0 ]; then
        printf 'SKIP'
        return 0
    fi
    r_out=$( ( od -An -v -tu1 < "$1" |
        awk '{
            for (i = 1; i <= NF; i++) {
                if ($i == 0) { r++; if (r > m) m = r } else { r = 0 }
            }
        } END { print m + 0 }' ) 2>/dev/null )
    if [ -n "$r_out" ]; then
        printf '%s' "$r_out"
    else
        printf 'SKIP'
    fi
}

# mem_openable PID -> succeeds when /proc/<pid>/mem opens for this process
mem_openable() {
    ( : < "/proc/$1/mem" ) 2>/dev/null
}

# map_of_addr PID DECIMAL_ADDR -> the /proc/<pid>/maps line holding ADDR,
# with the field separators turned into '|', or SKIP
map_of_addr() {
    ma_pid=$1
    ma_want=$2
    ma_out=$( ( while read -r ma_line; do
        ma_range=$(printf '%s' "$ma_line" | awk '{ print $1 }')
        ma_lo=$(( 0x${ma_range%%-*} )) 2>/dev/null || continue
        ma_hi=$(( 0x${ma_range##*-} )) 2>/dev/null || continue
        if [ "$ma_want" -ge "$ma_lo" ] && [ "$ma_want" -lt "$ma_hi" ]; then
            printf '%s' "$ma_line" | tr ' ' '|'
            exit 0
        fi
    done < "/proc/$ma_pid/maps" ) 2>/dev/null )
    if [ -n "$ma_out" ]; then
        printf '%s' "$ma_out"
    else
        printf 'SKIP'
    fi
}

# auxv_execfn_ptr PID -> AT_EXECFN as a plain decimal number, or empty
auxv_execfn_ptr() {
    ( od -An -v -tx8 < "/proc/$1/auxv" |
        awk '{
            for (i = 1; i <= NF; i++) {
                c++
                v = $i
                sub(/^0+/, "", v)
                if (v == "") v = "0"
                if (c % 2 == 1) { t = v } else if (t == "1f") { print v; exit }
            }
        }' ) 2>/dev/null
}

# execfn_has_canary PID CANARY -> 1, 0 or SKIP.  AT_EXECFN is read from
# /proc/<pid>/auxv and the string it points at from /proc/<pid>/mem.
execfn_has_canary() {
    eh_pid=$1
    eh_can=$2
    if [ ! -r "/proc/$eh_pid/auxv" ]; then
        printf 'SKIP'
        return 0
    fi
    eh_ptr=$(auxv_execfn_ptr "$eh_pid")
    if [ -z "$eh_ptr" ]; then
        printf 'SKIP'
        return 0
    fi
    if ! mem_openable "$eh_pid"; then
        printf 'SKIP'
        return 0
    fi
    eh_off=$(( 0x$eh_ptr )) 2>/dev/null || { printf 'SKIP'; return 0; }
    # Stop at the first NUL: AT_EXECFN is one string, and the bytes after it
    # in the same page are other strings that may legitimately hold the
    # canary (the restored argv of a masked process lives there).
    eh_str=$( ( dd if="/proc/$eh_pid/mem" bs=1 skip="$eh_off" count=256 |
        tr '\0' '\n' | head -1 ) 2>/dev/null )
    if [ -z "$eh_str" ]; then
        printf 'SKIP'
        return 0
    fi
    case "$eh_str" in
        *"$eh_can"*) printf '1' ;;
        *) printf '0' ;;
    esac
}

# mem_scan PID CANARY -> "hits scanned".  Every readable mapping is read page
# by page and searched for the canary.  `strings /proc/<pid>/mem` is not used
# because it seeks from offset 0, page 0 is unmapped, the read fails with EIO
# and it reports nothing at all, even for a process whose canary sits in its
# stack.  The strings figure is measured separately so that limit is visible
# rather than implied.  The name of each mapping that did hold the canary is
# written to $T/memhits for the human table.
mem_scan() {
    mc_pid=$1
    mc_can=$2
    : > "$T/memhits"
    if [ "$HAVE_DD" = 0 ]; then
        printf 'SKIP -1'
        return 0
    fi
    if ! mem_openable "$mc_pid"; then
        printf 'SKIP -1'
        return 0
    fi
    mc_hits=0
    mc_total=0
    while read -r mc_line; do
        mc_perms=$(printf '%s' "$mc_line" | awk '{ print $2 }')
        case "$mc_perms" in
            r*) ;;
            *) continue ;;
        esac
        mc_range=$(printf '%s' "$mc_line" | awk '{ print $1 }')
        mc_lo=$(( 0x${mc_range%%-*} )) 2>/dev/null || continue
        mc_hi=$(( 0x${mc_range##*-} )) 2>/dev/null || continue
        mc_n=$(( mc_hi - mc_lo ))
        [ "$mc_n" -le 0 ] && continue
        # A cap for pathological mappings, not a normal limit: a shell
        # payload maps well under 1 MiB per segment.
        [ "$mc_n" -gt 268435456 ] && mc_n=268435456
        mc_total=$(( mc_total + mc_n ))
        if ( dd if="/proc/$mc_pid/mem" bs=4096 skip=$(( mc_lo / 4096 )) \
            count=$(( (mc_n + 4095) / 4096 )) | tr '\0' '\n' | grep -q -- "$mc_can" ) 2>/dev/null; then
            mc_hits=$(( mc_hits + 1 ))
            mc_name=$(printf '%s' "$mc_line" | awk '{
                n = 0
                for (i = 6; i <= NF; i++) n = i
                if (n == 0) print "[anon]"; else print $n
            }')
            printf '%s(%s) ' "$mc_name" "$mc_perms" >> "$T/memhits"
        fi
    done < "/proc/$mc_pid/maps" 2>/dev/null
    printf '%s %s' "$mc_hits" "$mc_total"
}

# strings_bytes PID -> what `strings /proc/<pid>/mem` produces, in bytes
strings_bytes() {
    if [ "$HAVE_STRINGS" = 0 ]; then
        printf 'SKIP'
        return 0
    fi
    if ! mem_openable "$1"; then
        printf 'SKIP'
        return 0
    fi
    s_out=$( ( strings "/proc/$1/mem" | wc -c ) 2>/dev/null | tr -d ' ' )
    if [ -n "$s_out" ]; then
        printf '%s' "$s_out"
    else
        printf 'SKIP'
    fi
}

# await_payload SUPERVISOR LABEL VARIANT -> pid of the live payload.
#
# The payload of a variant is the direct child of the holder that carries
# the label.  When no such process exists within one second but a direct
# child does, that child is used and a note on stderr says so.  The parentage
# fallback keeps a broken label visible in the table (the canary and the real
# comm then appear in the columns) instead of hiding it behind a row of SKIP,
# and the note says which of the two happened.  The search runs for one
# second, well inside the payload's own lifetime.
await_payload() {
    ap_label=""
    ap_any=""
    ap_n=0
    while [ "$ap_n" -lt 20 ]; do
        for ap_d in /proc/[0-9]*; do
            ap_p=${ap_d#/proc/}
            [ "$ap_p" = "$$" ] && continue
            ap_pp=$(sed -n 's/^PPid:[[:space:]]*//p' "$ap_d/status" 2>/dev/null)
            [ "$ap_pp" = "$1" ] || continue
            [ -z "$ap_any" ] && ap_any=$ap_p
            if [ -z "$ap_label" ] &&
                [ "$(cat "$ap_d/comm" 2>/dev/null)" = "$2" ]; then
                ap_label=$ap_p
            fi
        done
        if [ -n "$ap_label" ]; then
            printf '%s' "$ap_label"
            return 0
        fi
        ap_n=$((ap_n + 1))
        sleep 0.05 2>/dev/null || sleep 1
    done
    if [ -n "$ap_any" ] && [ -d "/proc/$ap_any" ]; then
        note "$3: no direct child carries the label; the row describes child $ap_any, comm=[$(cat "/proc/$ap_any/comm" 2>/dev/null)]"
        printf '%s' "$ap_any"
        return 0
    fi
    note "$3: the holder produced no living child, so the row is SKIP"
    return 1
}

note() {
    printf 'note: %s\n' "$1" >&2
}

# ------------------------------------------------------------ tool guards
# A column whose tool is absent prints SKIP, never a zero.  The flags are
# set once so the row builder does not repeat the lookup per field.
HAVE_OD=0; command -v od >/dev/null 2>&1 && HAVE_OD=1
HAVE_DD=0; command -v dd >/dev/null 2>&1 && HAVE_DD=1
HAVE_TR=0; command -v tr >/dev/null 2>&1 && HAVE_TR=1
HAVE_STRINGS=0; command -v strings >/dev/null 2>&1 && HAVE_STRINGS=1
HAVE_PS=0; command -v ps >/dev/null 2>&1 && HAVE_PS=1

# ------------------------------------------------------------ the row

# emit_row VARIANT PID
# Prints one ROW line and appends the same values, tab separated, to the
# human table.  PID may be empty, which marks every column SKIP.
emit_row() {
    er_variant=$1
    er_pid=$2
    if [ -z "$er_pid" ] || [ ! -d "/proc/$er_pid" ]; then
        printf 'ROW %s SKIP SKIP SKIP SKIP SKIP SKIP SKIP SKIP SKIP SKIP SKIP SKIP SKIP SKIP\n' \
            "$er_variant"
        printf '%s\tSKIP\tSKIP\tSKIP\tSKIP\tSKIP\tSKIP\tSKIP\tSKIP\tSKIP\tSKIP\tSKIP\tSKIP\tSKIP\tSKIP\tSKIP\tSKIP\n' \
            "$er_variant" >> "$T/human"
        return 0
    fi
    er_comm=$(tr -d '\n' < "/proc/$er_pid/comm" 2>/dev/null | tr -c 'A-Za-z0-9._-' '_')
    [ -n "$er_comm" ] || er_comm='SKIP'
    er_exe=$(readlink "/proc/$er_pid/exe" 2>/dev/null)
    if [ -n "$er_exe" ]; then
        er_exe=$(printf '%s' "$er_exe" | tr ' ' '|')
    else
        er_exe='SKIP'
    fi
    er_tracer=$(sed -n 's/^TracerPid:[[:space:]]*//p' "/proc/$er_pid/status" 2>/dev/null)
    [ -n "$er_tracer" ] || er_tracer='SKIP'
    er_cmd="/proc/$er_pid/cmdline"
    er_env="/proc/$er_pid/environ"
    er_cmdbytes=$(bytes "$er_cmd")
    er_envbytes=$(bytes "$er_env")
    er_nul=$(nul_count "$er_cmd")
    er_run=$(nul_run "$er_cmd")
    er_can_cmd=$(has "$er_cmd" "$CAN")
    er_can_env=$(has "$er_env" "$CAN")
    er_aux=$(execfn_has_canary "$er_pid" "$CAN")
    er_span='SKIP'
    er_vma='SKIP'
    er_fields=$(stat_fields "$er_pid")
    if [ -n "$er_fields" ]; then
        er_as=$(printf '%s' "$er_fields" | awk '{ print $1 }')
        er_ae=$(printf '%s' "$er_fields" | awk '{ print $2 }')
        case "$er_as$er_ae" in
            *[!0-9]*) ;;
            '') ;;
            *)
                er_span=$(( er_ae - er_as ))
                er_vma=$(map_of_addr "$er_pid" "$er_as")
                ;;
        esac
    fi
    er_mem=$(mem_scan "$er_pid" "$CAN")
    case "$er_mem" in
        SKIP*) er_memflag='SKIP'; er_scanned='SKIP' ;;
        *)
            er_memflag=$(printf '%s' "$er_mem" | awk '{ print ($1 > 0) ? 1 : 0 }')
            er_scanned=$(printf '%s' "$er_mem" | awk '{ print $2 }')
            ;;
    esac
    er_hits=$(cat "$T/memhits" 2>/dev/null)
    [ -n "$er_hits" ] || er_hits='-'
    er_str=$(strings_bytes "$er_pid")
    printf 'ROW %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n' \
        "$er_variant" "$er_pid" "$er_comm" "$er_exe" "$er_tracer" \
        "$er_cmdbytes" "$er_span" "$er_nul" "$er_run" \
        "$er_can_cmd" "$er_can_env" "$er_envbytes" "$er_aux" \
        "$er_vma" "$er_memflag"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$er_variant" "$er_pid" "$er_comm" "$er_exe" "$er_tracer" \
        "$er_cmdbytes" "$er_span" "$er_nul" "$er_run" "$er_can_cmd" \
        "$er_can_env" "$er_envbytes" "$er_aux" "$er_vma" "$er_memflag" \
        "$er_scanned" "$er_str" "$er_hits" >> "$T/human"
    return 0
}

# ------------------------------------------------------------ variants

printf 'FIELDS variant pid comm exe tracer_pid cmdline_bytes stat_arg_span nul_count nul_maxrun canary_in_cmdline canary_in_environ environ_bytes auxv_execfn_contains_canary argstart_vma mem_canary_readable\n'
: > "$T/human"

# ------------------------------------------------------------- control
# The canary is a real argv element and a real environment entry, and the
# job is not supervised.  Every detector below must fire on this row,
# otherwise a quiet redacted row would prove nothing.
export "$ENVNAME=$CAN"
export PMK_COMPARE_OTHER=canary-value
/bin/sh -c "sleep $HOLD" "$CAN" >/dev/null 2>&1 &
PAYLOAD=$!
sleep 0.4
emit_row control "$PAYLOAD"
kill -9 "$PAYLOAD" 2>/dev/null
PAYLOAD=""
wait 2>/dev/null

# ------------------------------------------------------------ redacted
"$TOOL" run --label "$LABEL" -- /bin/sh -c "sleep $HOLD" "$CAN" \
    >/dev/null 2>"$T/redacted.err" &
SUP=$!
PAYLOAD=$(await_payload "$SUP" "$LABEL" redacted) || PAYLOAD=""
emit_row redacted "$PAYLOAD"
SUP_MAPS=$(maps_bytes "$SUP")
PAY_MAPS=$(maps_bytes "$PAYLOAD")
printf 'SUPERVISOR redacted maps_bytes=%s payload_maps_bytes=%s\n' "$SUP_MAPS" "$PAY_MAPS"
kill -9 "$SUP" 2>/dev/null
[ -n "$PAYLOAD" ] && kill -9 "$PAYLOAD" 2>/dev/null
PAYLOAD=""
SUP=""
wait 2>/dev/null

# ------------------------------------------------------ redacted-nodumpable
# The flag's other half: the payload itself is non-dumpable, and the
# supervisor is non-dumpable in both variants.
"$TOOL" run --label "$LABEL" --no-dumpable -- /bin/sh -c "sleep $HOLD" "$CAN" \
    >/dev/null 2>"$T/nodump.err" &
SUP=$!
PAYLOAD=$(await_payload "$SUP" "$LABEL" redacted-nodumpable) || PAYLOAD=""
emit_row redacted-nodumpable "$PAYLOAD"
SUP_NODUMP=$(maps_bytes "$SUP")
PAY_NODUMP=$(maps_bytes "$PAYLOAD")
printf 'SUPERVISOR redacted-nodumpable maps_bytes=%s payload_maps_bytes=%s\n' "$SUP_NODUMP" "$PAY_NODUMP"
kill -9 "$SUP" 2>/dev/null
[ -n "$PAYLOAD" ] && kill -9 "$PAYLOAD" 2>/dev/null
PAYLOAD=""
SUP=""
wait 2>/dev/null

# The observer is not blind: this shell's own maps are readable.
SELF_MAPS=$(maps_bytes $$)
printf 'SUPERVISOR control maps_bytes=%s\n' "$SELF_MAPS"

# ---------------------------------------------------- map_files and the window
# The map_files entry and the script window are the two numbers the README
# calls unmeasured.  Both are measured here, not asserted by a probe.
MAP_FAIL=0
map_files_read() {  # SUP IS_REXEC -> "range|target" or "|"
    mf_pid=$(await_payload "$1" "$LABEL" map-files) || { printf '|'; return 0; }
    if [ "$2" = 1 ]; then
        mf_range=$(awk '$6 ~ /memfd/ { print $1; exit }' "/proc/$mf_pid/maps" 2>/dev/null)
    else
        mf_range=$(awk '$6 ~ /testcases/ { print $1; exit }' "/proc/$mf_pid/maps" 2>/dev/null)
    fi
    if [ -z "$mf_range" ]; then
        printf '|'
        return 0
    fi
    mf_target=$(readlink "/proc/$mf_pid/map_files/$mf_range" 2>/dev/null)
    printf '%s|%s' "$mf_range" "$mf_target"
}
"$TOOL" -q -l "$LABEL" --rexec "$CASES" sleeper >/dev/null 2>&1 &
SUP=$!
MF_REXEC=$(map_files_read "$SUP" 1)
kill -9 "$SUP" 2>/dev/null
SUP=""
wait 2>/dev/null
"$TOOL" -q -l "$LABEL" "$CASES" sleeper >/dev/null 2>&1 &
SUP=$!
MF_PLAIN=$(map_files_read "$SUP" 0)
kill -9 "$SUP" 2>/dev/null
SUP=""
wait 2>/dev/null
printf 'MAP_FILES rexec_range=%s rexec_target=%s plain_range=%s plain_target=%s\n' \
    "${MF_REXEC%%|*}" "${MF_REXEC#*|}" "${MF_PLAIN%%|*}" "${MF_PLAIN#*|}"
case "${MF_REXEC#*|}" in
    */memfd:*|/memfd:*) ;;
    *) [ -z "${MF_REXEC#*|}" ] || MAP_FAIL=1 ;;
esac
case "${MF_PLAIN#*|}" in
    */testcases|*testcases) ;;
    *) [ -z "${MF_PLAIN#*|}" ] || MAP_FAIL=1 ;;
esac

# SCRIPT-WINDOW: a `#!` payload's interpreter line stays in /proc until
# the completion stop.  The observer here is the tracer's own verbose
# log: the completion-stop line is the time from the exec stop to the
# resume, which is the part of the window the supervisor controls.  The
# real argv is visible for at least that long.
printf '#!/bin/sh\nsleep 0.1\n' > "$T/window.sh"
chmod 755 "$T/window.sh"
"$TOOL" -v -l "$LABEL" "$T/window.sh" >/dev/null 2>"$T/window.err"
sw_pid=$(sed -n 's/.*pid \([0-9]*\): script\/unknown exec.*/\1/p' "$T/window.err" | head -1)
sw_us=""
if [ -n "$sw_pid" ]; then
    sw_us=$(sed -n "s/.*pid $sw_pid: completion-stop \([0-9]*\)us.*/\1/p" "$T/window.err" | head -1)
fi
printf 'SCRIPT-WINDOW window_us=%s method=completion-stop\n' "${sw_us:-SKIP}"

# DETACH-TREE: a three-deep tree under --detach.  The tool sees the
# payload's exec and detaches it; the payload's child and grandchild are
# never seized, so their markers stay visible.  The counts are taken from
# the run: `labelled` is the number of execs the supervisor redacted
# itself (its verbose `: redacted` lines), `unlabelled` is the number of
# markers this observer still saw after the detach, which is the coverage
# loss the flag trades for TracerPid 0.
DETACH_FAIL=0
DL='detach-tree'
"$TOOL" -v -l "$DL" --detach -- /bin/sh -c "/bin/sh -c '$CASES sleeper MK-DT-GRAND & sleep 0.6'; $CASES sleeper MK-DT-CHILD & sleep 0.6" >/dev/null 2>"$T/detach.err" &
SUP=$!
seen_g=0
seen_c=0
i=0
while [ "$i" -lt 20 ]; do
    i=$((i + 1))
    [ "$(sightings MK-DT-GRAND)" -ge 1 ] && seen_g=1
    [ "$(sightings MK-DT-CHILD)" -ge 1 ] && seen_c=1
    sleep 0.05
done
wait "$SUP" 2>/dev/null
SUP=""
detached=$(sed -n 's/^pmask: \([0-9]*\) tracee(s) left detached.*/\1/p' "$T/detach.err" | head -1)
labelled=$(grep -c ': redacted$' "$T/detach.err" 2>/dev/null)
[ -n "$labelled" ] || labelled=0
unlabelled=$((seen_g + seen_c))
printf 'DETACH-TREE labelled=%s unlabelled=%s visible_grand=%s visible_child=%s detached=%s\n' \
    "$labelled" "$unlabelled" "$seen_g" "$seen_c" "${detached:-0}"
[ "$seen_g" = 1 ] && [ "$seen_c" = 1 ] && [ "${detached:-0}" = 1 ] || DETACH_FAIL=1
# A pattern that stopped matching would print labelled=0 and pass the
# three flags above, so the count itself is asserted.
[ "$labelled" -ge 1 ] || DETACH_FAIL=1
# The two sleepers were never followed, so nothing else will reap them.  A
# live one holds tests/testcases open for execution and makes the next
# suite's copy of the binary fail with ETXTBSY.
for m in MK-DT-GRAND MK-DT-CHILD; do
    for d in /proc/[0-9]*; do
        [ "$(cat "$d/comm" 2>/dev/null)" = testcases ] || continue
        case "$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null)" in
            *"$m"*) kill -9 "${d#/proc/}" 2>/dev/null ;;
        esac
    done
done

# AUDIT: the residue report on a trivial run.  The header, one row and
# the residue line are the contract; a row that cannot read an interface
# prints `not reachable`, never a zero.
AUDIT_FAIL=0
audit_out=$("$TOOL" --audit -q -- /bin/true 2>/dev/null)
case "$audit_out" in
    *"pmask audit: header"*"pmask audit: pid="*"pmask audit: residue:"*)
        pass_msg="audit-report"
        ;;
    *)
        AUDIT_FAIL=1
        pass_msg="audit-report-missing: $(printf '%s' "$audit_out" | tr '\n' '|' | cut -c1-160)"
        ;;
esac
printf 'AUDIT %s\n' "$pass_msg"

# ------------------------------------------------------ redacted-detach
# This row exists only when the binary advertises a detach flag, which is
# how the harness stays honest on a revision that has no such flag.  When
# --help does not name one the row is marked SKIP instead of inventing a
# flag or copying the redacted row.
if "$TOOL" --help 2>&1 | grep -q -- '--detach'; then
    "$TOOL" run --label "$LABEL" --detach -- /bin/sh -c "sleep $HOLD" "$CAN" \
        >/dev/null 2>"$T/detach.err" &
    SUP=$!
    PAYLOAD=$(await_payload "$SUP" "$LABEL" redacted-detach) || PAYLOAD=""
    emit_row redacted-detach "$PAYLOAD"
    kill -9 "$SUP" 2>/dev/null
    [ -n "$PAYLOAD" ] && kill -9 "$PAYLOAD" 2>/dev/null
    PAYLOAD=""
    SUP=""
    wait 2>/dev/null
else
    printf 'ROW redacted-detach SKIP SKIP SKIP SKIP SKIP SKIP SKIP SKIP SKIP SKIP SKIP SKIP SKIP SKIP\n'
    printf '%s\tSKIP\tSKIP\tSKIP\tSKIP\tSKIP\tSKIP\tSKIP\tSKIP\tSKIP\tSKIP\tSKIP\tSKIP\tSKIP\tSKIP\tSKIP\tSKIP\n' \
        redacted-detach >> "$T/human"
fi

# ---------------------------------------------------------- human table
printf '\n'
printf 'human table: one row per variant, the same values as the ROW lines\n'
printf '%-16s %-7s %-14s %-6s %-9s %-8s %-5s %-7s %-10s %-10s %-9s %-11s %-12s %-6s %-10s\n' \
    variant pid comm tracer cmd_bytes arg_span nuls nul_run canary_cmd canary_env env_bytes auxv_canary mem_canary scanned strings_bytes
while IFS='	' read -r hv hp hc hx ht hcb hs hn hr hcc hce heb hau hvm hmem hsc hst hits; do
    printf '%-16s %-7s %-14s %-6s %-9s %-8s %-5s %-7s %-10s %-10s %-9s %-11s %-12s %-6s %-10s\n' \
        "$hv" "$hp" "$hc" "$ht" "$hcb" "$hs" "$hn" "$hr" "$hcc" "$hce" "$heb" "$hau" "$hmem" "$hsc" "$hst"
done < "$T/human"

printf '\n'
printf 'detail: exe, the mapping that holds arg_start, and the mappings that\n'
printf 'detail: hold the canary in /proc/<pid>/mem, per variant\n'
while IFS='	' read -r hv hp hc hx ht hcb hs hn hr hcc hce heb hau hvm hmem hsc hst hits; do
    printf '%-16s exe=[%s]\n' "$hv" "$hx"
    printf '%-16s argstart_vma=[%s]\n' "" "$hvm"
    printf '%-16s mem_canary_in=[%s]\n' "" "$hits"
done < "$T/human"

printf '\n'
printf 'canary %s was an argv element of the job and PMK_COMPARE_CANARY held it\n' "$CAN"
printf 'in the environment.\n'
printf 'mem_canary comes from a page-by-page scan of every readable mapping in\n'
printf '/proc/<pid>/mem.  strings(/proc/<pid>/mem) is not used because it seeks\n'
printf 'from offset 0, page 0 is unmapped, the read fails with EIO and it\n'
printf 'reports nothing at all, even for the control whose canary sits in its\n'
printf 'stack mapping.  The strings_bytes column is that figure, and it is why\n'
printf 'the column exists.\n'

# The supervisor is non-dumpable for the life of the session, so a
# same-uid peer cannot read its maps (it holds the real argv of every
# tracee).  The payload follows --no-dumpable: readable without it,
# refused with it.  Root is not a same-uid peer and cannot test this.
sup_fail=""
if [ "$(id -u)" != 0 ]; then
    [ "$SELF_MAPS" = REFUSED ] && sup_fail="$sup_fail control-not-readable"
    [ "$SUP_MAPS" = REFUSED ] || sup_fail="$sup_fail supervisor-readable"
    [ "$SUP_NODUMP" = REFUSED ] || sup_fail="$sup_fail supervisor-readable-nodumpable"
    [ "$PAY_MAPS" != REFUSED ] || sup_fail="$sup_fail payload-refused-without-flag"
    [ "$PAY_NODUMP" = REFUSED ] || sup_fail="$sup_fail payload-readable-with-flag"
fi
# These three read /proc and run the tool; they do not need a same-uid
# peer, so a root run asserts them too.
[ "$MAP_FAIL" = 0 ] || sup_fail="$sup_fail map-files-target"
[ "$DETACH_FAIL" = 0 ] || sup_fail="$sup_fail detach-tree"
[ "$AUDIT_FAIL" = 0 ] || sup_fail="$sup_fail audit-report"
if [ -n "$sup_fail" ]; then
    printf 'COMPARE: FAIL%s\n' "$sup_fail"
    exit 1
fi

printf 'COMPARE: OK\n'
exit 0
