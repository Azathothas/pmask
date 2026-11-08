#!/bin/sh
# ============================================================================
# pmask store suite -- the encrypted store's directory, temporary file,
# locking and KDF-bound behaviour, driven through the real CLI.
#
# Every group here is decided by observing a file, a mode, an exit status or
# a process, never by trusting what the tool says it did.
#
#   S1  a fresh HOME gets a 0700 directory chain and a 0600 store
#   S2  an existing store directory keeps its mode
#   S3  a pre-planted symlink at the old temporary path is not followed
#   S4  a stale .tmp with mode 0644 is not reused and never widens the store
#   S5  a group/other writable directory needs PMASK_ALLOW_SHARED_DIR=1
#   S6  two concurrent `store set` runs: one success, one "store is busy"
#   S7  a crafted m_cost of 2^32-1 fails fast with a message naming m_cost
#   S8  the m_cost ceiling is overridable with PMASK_KDF_MAX_MEM
#   S9  a store below the KDF baseline fails without the weak opt-in
#   S10 sequential writers accumulate and the newer entry survives
#   S11 an unusable temporary directory leaves the store intact
#   S12 the passphrase is one line: a second line is not hashed
#   S13 a NUL byte in the passphrase file is refused, naming the NUL
#   S14 a first line above the limit is refused, naming the limit
#
# The suite uses its own HOME and its own store paths under /tmp and needs
# no root, no VM and no ptrace.
# ============================================================================
set -u
cd "$(dirname "$0")"

TOOL="${PMASK_TEST_BIN:-./pmask}"
if [ ! -x "$TOOL" ]; then
    echo "FATAL: no pmask binary at $TOOL (run cargo build --bins)"
    exit 2
fi

FAIL=0
T="/tmp/mkstore.$$"
if ! mkdir -p "$T"; then
    echo "FATAL: cannot create $T"
    exit 2
fi
chmod 700 "$T"

cleanup() {
    chmod -R u+rwx "$T" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT HUP INT TERM

pass() { echo "PASS $*"; }
fail() {
    echo "FAIL $*"
    FAIL=$((FAIL + 1))
}
skip() { echo "SKIP $*"; }

# mode_of PATH -> the permission bits of PATH, following no symlink
mode_of() {
    stat -c '%a' "$1" 2>/dev/null
}

# wait_for_file FILE SECONDS -> 0 once FILE exists
wait_for_file() {
    wf_n=0
    wf_lim=$(($2 * 100))
    while [ "$wf_n" -lt "$wf_lim" ]; do
        [ -e "$1" ] && return 0
        wf_n=$((wf_n + 1))
        sleep 0.01
    done
    return 1
}

# le32 VALUE -> four little-endian bytes as printf escapes
le32() {
    le_v=$1
    le_a=$((le_v % 256))
    le_v=$((le_v / 256))
    le_b=$((le_v % 256))
    le_v=$((le_v / 256))
    le_c=$((le_v % 256))
    le_v=$((le_v / 256))
    le_d=$((le_v % 256))
    printf '\\%03o\\%03o\\%03o\\%03o' "$le_a" "$le_b" "$le_c" "$le_d"
}

# le64 VALUE -> eight little-endian bytes as printf escapes
le64() {
    le_v=$1
    le_s=""
    le_i=0
    while [ "$le_i" -lt 8 ]; do
        le_s="$le_s$(printf '\\%03o' $((le_v % 256)))"
        le_v=$((le_v / 256))
        le_i=$((le_i + 1))
    done
    printf '%s' "$le_s"
}

# craft_store FILE M_COST T_COST P_COST
# Write a store with a valid magic and header framing, the given KDF
# parameters, and ciphertext that will not authenticate.  The KDF bounds are
# checked before any decryption, so the header alone decides the outcome.
# %b is required: %s would write the backslash escapes literally.
craft_store() {
    {
        printf '%b' 'PMASKSTORE1\000\000\000\000\000'
        printf '%b' "$(le32 "$2")"
        printf '%b' "$(le32 "$3")"
        printf '%b' "$(le32 "$4")"
        printf '%b' '\020'
        printf '%b' 'abcdefghijklmnop'
        printf '%b' '\030'
        printf '%b' 'abcdefghijklmnopqrstuvwx'
        printf '%b' "$(le64 16)"
        printf '%b' 'abcdefghijklmnop'
    } > "$1"
}

# param_of FILE -> the three little-endian u32 KDF fields, space separated
param_of() {
    od -An -tu4 -j16 -N12 "$1" 2>/dev/null | tr -s ' ' | sed 's/^ //; s/ $//'
}

PP="$T/pass"
printf 'store-suite-passphrase\n' > "$PP"
chmod 600 "$PP"

# ------------------------------------------------- S1: fresh account
# Catches: save() failing with ENOENT when the store directory is missing.
FRESH="$T/fresh-home"
if mkdir -p "$FRESH" && chmod 700 "$FRESH"; then
    out=$(HOME="$FRESH" XDG_DATA_HOME= PMASK_PASSPHRASE_FILE= sh -c \
        "unset XDG_DATA_HOME; '$TOOL' store init --passphrase-file '$PP'" 2>&1)
    rc=$?
    store="$FRESH/.local/share/pmask/store.enc"
    if [ "$rc" != 0 ]; then
        fail "s1-init-on-fresh-home (rc=$rc out=$out)"
    elif [ ! -f "$store" ]; then
        fail "s1-init-on-fresh-home (no store at $store)"
    else
        pass "s1-init-on-fresh-home"
        [ "$(mode_of "$store")" = "600" ] && pass "s1-store-is-0600" \
            || fail "s1-store-is-0600 (got $(mode_of "$store"))"
        [ "$(mode_of "$FRESH/.local/share/pmask")" = "700" ] \
            && pass "s1-store-dir-is-0700" \
            || fail "s1-store-dir-is-0700 (got $(mode_of "$FRESH/.local/share/pmask"))"
        [ "$(mode_of "$FRESH/.local")" = "700" ] \
            && [ "$(mode_of "$FRESH/.local/share")" = "700" ] \
            && pass "s1-created-chain-is-0700" \
            || fail "s1-created-chain-is-0700 (.local=$(mode_of "$FRESH/.local") .local/share=$(mode_of "$FRESH/.local/share"))"
    fi
    # the whole store path works on the same fresh HOME, not only init
    printf 'first-value' | HOME="$FRESH" sh -c \
        "unset XDG_DATA_HOME; '$TOOL' store set A --passphrase-file '$PP'" >/dev/null 2>&1
    got=$(HOME="$FRESH" sh -c \
        "unset XDG_DATA_HOME; '$TOOL' store get A --passphrase-file '$PP'" 2>/dev/null)
    [ "$got" = "first-value" ] && pass "s1-set-and-get-on-fresh-home" \
        || fail "s1-set-and-get-on-fresh-home (got [$got])"
else
    fail "s1-init-on-fresh-home (cannot build the fixture)"
fi

# ------------------------------------------------- S2: existing directory
# Catches: chmod-ing a directory this tool did not create.
EXIST="$T/exist"
mkdir -p "$EXIST"
chmod 755 "$EXIST"
printf 'v' | "$TOOL" store set A --store "$EXIST/s.enc" --passphrase-file "$PP" >/dev/null 2>&1
if [ "$(mode_of "$EXIST")" = "755" ]; then
    pass "s2-existing-directory-mode-untouched (still 755)"
else
    fail "s2-existing-directory-mode-untouched (mode is now $(mode_of "$EXIST"))"
fi

# --------------------------------------- S3: planted symlink at old path
# Catches: a predictable temporary name whose write follows a symlink an
# attacker planted, overwriting or truncating the target.
LINK="$T/link"
mkdir -p "$LINK"
chmod 700 "$LINK"
SENT="$T/sentinel"
printf 'SENTINEL-DO-NOT-TOUCH' > "$SENT"
printf 'v' | "$TOOL" store set SEED --store "$LINK/s.enc" --passphrase-file "$PP" >/dev/null 2>&1
for old in "$LINK/s.tmp" "$LINK/s.enc.tmp"; do
    ln -s "$SENT" "$old"
done
printf 'planted-value' | "$TOOL" store set AFTER --store "$LINK/s.enc" --passphrase-file "$PP" >/dev/null 2>&1
rc=$?
content=$(cat "$SENT" 2>/dev/null)
got=$("$TOOL" store get AFTER --store "$LINK/s.enc" --passphrase-file "$PP" 2>/dev/null)
if [ "$rc" != 0 ]; then
    fail "s3-planted-symlink-not-followed (set failed, rc=$rc)"
elif [ "$content" != "SENTINEL-DO-NOT-TOUCH" ]; then
    fail "s3-planted-symlink-not-followed (sentinel now [$content])"
elif [ "$got" != "planted-value" ]; then
    fail "s3-planted-symlink-not-followed (store holds [$got])"
elif [ ! -L "$LINK/s.enc.tmp" ]; then
    fail "s3-planted-symlink-not-followed (the planted link was replaced)"
else
    pass "s3-planted-symlink-not-followed (sentinel intact, store written)"
fi

# ------------------------------------------ S4: stale wide-mode temp file
# Catches: reusing an existing .tmp, so the ciphertext is written into a file
# that already exists with mode 0644 and is only narrowed afterwards.  The old
# predictable name was <store>.tmp, i.e. s.tmp for a store at s.enc, so both
# spellings are planted.
STALE="$T/stale"
mkdir -p "$STALE"
chmod 700 "$STALE"
printf 'stale-bytes' > "$STALE/s.tmp"
chmod 644 "$STALE/s.tmp"
printf 'stale-bytes' > "$STALE/s.enc.tmp"
chmod 644 "$STALE/s.enc.tmp"
printf 'wide-window-value' | "$TOOL" store set A --store "$STALE/s.enc" --passphrase-file "$PP" >/dev/null 2>&1
rc=$?
old_content=$(cat "$STALE/s.tmp" 2>/dev/null)
old_mode=$(mode_of "$STALE/s.tmp")
if [ "$rc" != 0 ]; then
    fail "s4-stale-temp-not-reused (set failed, rc=$rc)"
elif [ "$old_content" != "stale-bytes" ] || [ "$old_mode" != "644" ]; then
    fail "s4-stale-temp-not-reused (s.tmp reused: mode $old_mode, $(printf '%s' "$old_content" | wc -c) bytes)"
elif [ "$(mode_of "$STALE/s.enc")" != "600" ]; then
    fail "s4-stale-temp-not-reused (store mode $(mode_of "$STALE/s.enc"))"
elif [ "$(cat "$STALE/s.enc.tmp")" != "stale-bytes" ]; then
    fail "s4-stale-temp-not-reused (s.enc.tmp was written)"
else
    pass "s4-stale-temp-not-reused (store 0600, both stale files untouched)"
fi
# No temporary file is left behind by a successful write.
leftover=$(find "$STALE" -name '*.tmp.*' 2>/dev/null | wc -l | tr -d ' ')
[ "$leftover" = 0 ] && pass "s4-no-temp-file-left-behind" \
    || fail "s4-no-temp-file-left-behind ($leftover temporary files remain)"

# --------------------------------------------- S5: shared directory opt-in
# Catches: writing a store into a directory another account can rewrite,
# without the caller saying so.
SHARED="$T/shared"
mkdir -p "$SHARED"
chmod 777 "$SHARED"
printf 'v' | "$TOOL" store set A --store "$SHARED/s.enc" --passphrase-file "$PP" >"$T/shared.out" 2>"$T/shared.err"
rc=$?
if [ "$rc" = 0 ] || [ -f "$SHARED/s.enc" ]; then
    fail "s5-shared-directory-refused (rc=$rc, store exists: $([ -f "$SHARED/s.enc" ] && echo yes || echo no))"
elif ! grep -q "PMASK_ALLOW_SHARED_DIR" "$T/shared.err"; then
    fail "s5-shared-directory-refused (no opt-in named in stderr: $(tr '\n' '|' < "$T/shared.err"))"
else
    pass "s5-shared-directory-refused (rc=$rc, names the opt-in)"
fi
printf 'v' | PMASK_ALLOW_SHARED_DIR=1 "$TOOL" store set A --store "$SHARED/s.enc" --passphrase-file "$PP" >/dev/null 2>&1
rc=$?
if [ "$rc" = 0 ] && [ "$(mode_of "$SHARED/s.enc")" = "600" ]; then
    pass "s5-shared-directory-accepted-with-optin (store 0600)"
else
    fail "s5-shared-directory-accepted-with-optin (rc=$rc mode=$(mode_of "$SHARED/s.enc" 2>/dev/null))"
fi

# ------------------------------------------------------- S6: locking
# Catches: two writers both succeeding, or one blocking forever, or the
# store being left unreadable after the race.
#
# The two runs start from the same file and must not be able to overlap: the
# loser has to be refused by the flock, so its message must name the lock
# file.  A writer that merely lost the read-modify-write race would report
# the conflict instead, and that is a different defect with a different
# message, so the two are told apart here.
RACE="$T/race"
mkdir -p "$RACE"
chmod 700 "$RACE"
for i in 1 2 3; do
    "$TOOL" store init --store "$RACE/s$i.enc" --passphrase-file "$PP" >/dev/null 2>&1
    (
        printf 'race-alpha' | "$TOOL" store set ALPHA --store "$RACE/s$i.enc" --passphrase-file "$PP" \
            >"$RACE/out$i.a" 2>"$RACE/err$i.a"
        echo $? > "$RACE/rc$i.a"
    ) &
    r1=$!
    (
        printf 'race-beta' | "$TOOL" store set BETA --store "$RACE/s$i.enc" --passphrase-file "$PP" \
            >"$RACE/out$i.b" 2>"$RACE/err$i.b"
        echo $? > "$RACE/rc$i.b"
    ) &
    r2=$!
    waited=0
    while [ ! -f "$RACE/rc$i.a" ] || [ ! -f "$RACE/rc$i.b" ]; do
        if [ "$waited" -ge 900 ]; then
            break
        fi
        waited=$((waited + 1))
        sleep 0.01
    done
    kill -9 "$r1" "$r2" 2>/dev/null
    wait 2>/dev/null
    rc1=$(cat "$RACE/rc$i.a" 2>/dev/null)
    rc2=$(cat "$RACE/rc$i.b" 2>/dev/null)
    if [ -z "$rc1" ] || [ -z "$rc2" ]; then
        fail "s6-concurrent-set-one-wins (round $i: a writer never finished, rc=[$rc1] [$rc2])"
        continue
    fi
    ok=0
    busy=0
    for r in "$rc1" "$rc2"; do
        [ "$r" = 0 ] && ok=$((ok + 1))
        [ "$r" = 255 ] && busy=$((busy + 1))
    done
    lock_text=0
    for f in "$RACE/err$i.a" "$RACE/err$i.b"; do
        grep -q "store is busy" "$f" 2>/dev/null && grep -q "\.lock" "$f" 2>/dev/null \
            && lock_text=$((lock_text + 1))
    done
    if [ "$ok" != 1 ] || [ "$busy" != 1 ]; then
        fail "s6-concurrent-set-one-wins (round $i: rc=$rc1/$rc2, want one 0 and one 255)"
    elif [ "$lock_text" != 1 ]; then
        fail "s6-concurrent-set-one-wins (round $i: the loser was not stopped by the lock: $(cat "$RACE/err$i.a" "$RACE/err$i.b" 2>/dev/null | tr '\n' '|'))"
    elif ! "$TOOL" store list --store "$RACE/s$i.enc" --passphrase-file "$PP" >"$RACE/list$i" 2>&1; then
        fail "s6-concurrent-set-one-wins (round $i: the store no longer opens: $(tr '\n' '|' < "$RACE/list$i"))"
    else
        names=$(tr '\n' ',' < "$RACE/list$i")
        pass "s6-concurrent-set-one-wins (round $i: one success, one lock refusal, store opens with [$names])"
    fi
done

# ------------------------------------------------- S7: huge m_cost
# Catches: trusting the file's KDF parameters, so a crafted store asks for a
# 4 TiB derivation and the process dies of OOM or hangs.
CRAFT_BIG="$T/craft-big.enc"
craft_store "$CRAFT_BIG" 4294967295 2 1
params=$(param_of "$CRAFT_BIG")
start=$(date +%s)
"$TOOL" store list --store "$CRAFT_BIG" --passphrase-file "$PP" >"$T/big.out" 2>"$T/big.err"
rc=$?
elapsed=$(( $(date +%s) - start ))
if [ "$params" != "4294967295 2 1" ]; then
    fail "s7-crafted-m-cost (the fixture was not written: params [$params])"
elif [ "$rc" = 0 ]; then
    fail "s7-crafted-m-cost-rejected (rc=0, out=$(tr '\n' '|' < "$T/big.out"))"
elif ! grep -q "m_cost" "$T/big.err"; then
    fail "s7-crafted-m-cost-rejected (message does not name m_cost: $(tr '\n' '|' < "$T/big.err"))"
elif [ "$elapsed" -gt 5 ]; then
    fail "s7-crafted-m-cost-rejected (took ${elapsed}s, want under 5s)"
else
    pass "s7-crafted-m-cost-rejected (${elapsed}s, $(grep -o 'm_cost [0-9]* KiB exceeds the ceiling [0-9]* KiB' "$T/big.err" | head -1))"
fi

# ------------------------------------------------- S8: ceiling override
# Catches: a ceiling that cannot be raised, or one that ignores the value.
# The raised run must get *past* the bounds and fail later, on the tag.
CRAFT_HIGH="$T/craft-high.enc"
craft_store "$CRAFT_HIGH" 2097152 2 1
params=$(param_of "$CRAFT_HIGH")
"$TOOL" store list --store "$CRAFT_HIGH" --passphrase-file "$PP" >/dev/null 2>"$T/high.err"
rc_default=$?
PMASK_KDF_MAX_MEM=4194304 "$TOOL" store list --store "$CRAFT_HIGH" --passphrase-file "$PP" \
    >/dev/null 2>"$T/high2.err"
rc_raised=$?
low=$(grep -o 'ceiling [0-9]* KiB' "$T/high.err" | head -1)
if [ "$params" != "2097152 2 1" ]; then
    fail "s8-kdf-ceiling-overridable (the fixture was not written: params [$params])"
elif [ "$rc_default" = 0 ]; then
    fail "s8-kdf-ceiling-overridable (2 GiB accepted under the default 1 GiB ceiling)"
elif [ "$low" != "ceiling 1048576 KiB" ]; then
    fail "s8-kdf-ceiling-overridable (default run reports [$low])"
elif grep -q "KDF parameters refused" "$T/high2.err"; then
    fail "s8-kdf-ceiling-overridable (the raised run still refused the bounds: $(tr '\n' '|' < "$T/high2.err"))"
elif ! grep -q "cannot decrypt store" "$T/high2.err"; then
    fail "s8-kdf-ceiling-overridable (the raised run did not reach the tag check: $(tr '\n' '|' < "$T/high2.err"))"
else
    pass "s8-kdf-ceiling-overridable (default refused at [$low], raised run reached the tag check)"
fi
# a malformed ceiling is an error, not a silent fallback
PMASK_KDF_MAX_MEM=lots "$TOOL" store list --store "$CRAFT_HIGH" --passphrase-file "$PP" \
    >/dev/null 2>"$T/badenv.err"
rc=$?
if [ "$rc" != 0 ] && grep -q "PMASK_KDF_MAX_MEM" "$T/badenv.err"; then
    pass "s8-malformed-ceiling-refused"
else
    fail "s8-malformed-ceiling-refused (rc=$rc err=$(tr '\n' '|' < "$T/badenv.err"))"
fi

# ------------------------------------------------- S9: weak parameters
# Catches: a store below the baseline opening without the caller saying so.
CRAFT_WEAK="$T/craft-weak.enc"
craft_store "$CRAFT_WEAK" 8192 1 1
params=$(param_of "$CRAFT_WEAK")
"$TOOL" store list --store "$CRAFT_WEAK" --passphrase-file "$PP" >/dev/null 2>"$T/weak.err"
rc=$?
if [ "$params" != "8192 1 1" ]; then
    fail "s9-weak-store (the fixture was not written: params [$params])"
elif [ "$rc" = 0 ]; then
    fail "s9-weak-store-refused (rc=0: 8 MiB, t=1 was accepted)"
elif ! grep -q "PMASK_ALLOW_WEAK_KDF" "$T/weak.err"; then
    fail "s9-weak-store-refused (no opt-in named: $(tr '\n' '|' < "$T/weak.err"))"
else
    pass "s9-weak-store-refused (names PMASK_ALLOW_WEAK_KDF)"
fi
PMASK_ALLOW_WEAK_KDF=1 "$TOOL" store list --store "$CRAFT_WEAK" --passphrase-file "$PP" \
    >/dev/null 2>"$T/weak2.err"
rc=$?
# With the opt-in the bounds pass; the file then fails to authenticate.
if [ "$rc" != 0 ] && grep -q "KDF parameters refused" "$T/weak2.err"; then
    fail "s9-weak-store-optin-reaches-decrypt (still refused by the bounds: $(tr '\n' '|' < "$T/weak2.err"))"
elif [ "$rc" != 0 ] && grep -q "cannot decrypt store" "$T/weak2.err"; then
    pass "s9-weak-store-optin-reaches-decrypt (bounds passed, tag check is next)"
else
    fail "s9-weak-store-optin-reaches-decrypt (rc=$rc err=$(tr '\n' '|' < "$T/weak2.err"))"
fi

# --------------------------------------- S10: read-modify-write result
# Catches: a write that loses another writer's entry, or a store left with
# only the last writer's entries.  The CLI re-opens the store on every
# invocation, so the stale-handle conflict cannot be produced from the shell
# with two ordinary runs; that guard is covered by the unit tests
# (changed_store_is_not_overwritten, second_handle_writes_without_a_conflict).
# What is checked here is the outcome: sequential writers accumulate.
CONFLICT="$T/conflict"
mkdir -p "$CONFLICT"
chmod 700 "$CONFLICT"
"$TOOL" store init --store "$CONFLICT/s.enc" --passphrase-file "$PP" >/dev/null 2>&1
# Two ordinary writes in sequence: the second opens the first's result, so
# both must land.  This is the control for the conflict case below.
printf 'one' | "$TOOL" store set ONE --store "$CONFLICT/s.enc" --passphrase-file "$PP" >/dev/null 2>&1
printf 'two' | "$TOOL" store set TWO --store "$CONFLICT/s.enc" --passphrase-file "$PP" >/dev/null 2>&1
names=$("$TOOL" store list --store "$CONFLICT/s.enc" --passphrase-file "$PP" 2>/dev/null | tr '\n' ',')
[ "$names" = "ONE,TWO," ] && pass "s10-sequential-writes-both-land ($names)" \
    || fail "s10-sequential-writes-both-land (names [$names])"

# The store is replaced by a newer one, then written again.  Both entries
# must be there afterwards, and the newer one must not be lost.
STALE2="$T/stale-writer"
mkdir -p "$STALE2"
chmod 700 "$STALE2"
cp "$CONFLICT/s.enc" "$STALE2/s.enc"
chmod 600 "$STALE2/s.enc"
# A second, newer store placed at the same path with a later mtime.
sleep 1
cp "$CONFLICT/s.enc" "$STALE2/newer.enc"
printf 'newer' | "$TOOL" store set NEWER --store "$STALE2/newer.enc" --passphrase-file "$PP" >/dev/null 2>&1
mv "$STALE2/newer.enc" "$STALE2/s.enc"
printf 'stale' | "$TOOL" store set STALE --store "$STALE2/s.enc" --passphrase-file "$PP" >/dev/null 2>&1
rc=$?
# The CLI re-opens the file on every invocation, so it sees the new one and
# the write is allowed.  What must hold is that the newer entry survives.
kept=$("$TOOL" store get NEWER --store "$STALE2/s.enc" --passphrase-file "$PP" 2>/dev/null)
both=$("$TOOL" store list --store "$STALE2/s.enc" --passphrase-file "$PP" 2>/dev/null | tr '\n' ',')
if [ "$rc" != 0 ]; then
    fail "s10-newer-entry-survives-a-later-write (rc=$rc)"
elif [ "$kept" != "newer" ]; then
    fail "s10-newer-entry-survives-a-later-write (NEWER is [$kept])"
elif [ "$both" != "NEWER,ONE,STALE,TWO," ]; then
    fail "s10-newer-entry-survives-a-later-write (entries [$both], want every writer's entry)"
else
    pass "s10-newer-entry-survives-a-later-write ($both)"
fi

# ------------------------------------------------- S11: failed write path
# Catches: a temp file left behind, or the existing store damaged, when the
# directory refuses the temporary file.
BLOCKED="$T/blocked"
mkdir -p "$BLOCKED"
chmod 700 "$BLOCKED"
printf 'original' | "$TOOL" store set KEEP --store "$BLOCKED/s.enc" --passphrase-file "$PP" >/dev/null 2>&1
before=$(od -An -tx1 "$BLOCKED/s.enc" | md5sum)
# Make the directory read-only for this process.  The rename into it fails
# after the temporary file exists, which is the path that can leave a stray
# file holding ciphertext.
if [ "$(id -u)" != 0 ]; then
    chmod 500 "$BLOCKED"
    printf 'changed' | "$TOOL" store set KEEP --store "$BLOCKED/s.enc" --passphrase-file "$PP" \
        >/dev/null 2>"$T/blocked.err"
    rc=$?
    chmod 700 "$BLOCKED"
    after=$(od -An -tx1 "$BLOCKED/s.enc" | md5sum)
    kept=$("$TOOL" store get KEEP --store "$BLOCKED/s.enc" --passphrase-file "$PP" 2>/dev/null)
    stray=$(find "$BLOCKED" -name '*.tmp.*' 2>/dev/null | wc -l | tr -d ' ')
    if [ "$rc" = 0 ]; then
        fail "s11-readonly-directory-refuses-write (rc=0)"
    elif [ "$before" != "$after" ]; then
        fail "s11-readonly-directory-refuses-write (the store changed)"
    elif [ "$kept" != "original" ]; then
        fail "s11-readonly-directory-refuses-write (KEEP is [$kept])"
    elif [ "$stray" != 0 ]; then
        fail "s11-failed-write-leaves-no-temp-file ($stray temporary files remain)"
    else
        pass "s11-readonly-directory-refuses-write (store unchanged, still opens, no temp file)"
    fi
else
    echo "SKIP s11-readonly-directory-refuses-write (root ignores the directory mode)"
fi

# ------------------------------------- S12: the passphrase is one line
# Catches: reading the whole file and hashing every line, so a passphrase
# file that grew a second line (a comment, a trailing note) derives a
# different key and the store stops opening.
S1STORE="$FRESH/.local/share/pmask/store.enc"
if [ ! -f "$S1STORE" ]; then
    skip "s12-passphrase-file-uses-the-first-line (no store from S1)"
else
    PP2="$T/pass-two-lines"
    printf 'store-suite-passphrase\nsecond line is not part of it\n' > "$PP2"
    chmod 600 "$PP2"
    got=$("$TOOL" store get A --store "$S1STORE" --passphrase-file "$PP2" 2>"$T/s12.err")
    rc=$?
    if [ "$rc" = 0 ] && [ "$got" = "first-value" ]; then
        pass "s12-passphrase-file-uses-the-first-line"
    else
        fail "s12-passphrase-file-uses-the-first-line (rc=$rc out=[$got] err=$(tr '\n' '|' < "$T/s12.err"))"
    fi
fi

# ------------------------------------- S13: a NUL in the passphrase file
# Catches: hashing a binary file as if it were a passphrase, which derives
# a key the operator never chose and cannot reproduce.
if [ ! -f "$S1STORE" ]; then
    skip "s13-nul-passphrase-refused (no store from S1)"
else
    PPNUL="$T/pass-nul"
    printf 'store-suite-passphrase\000trailing\n' > "$PPNUL"
    chmod 600 "$PPNUL"
    "$TOOL" store list --store "$S1STORE" --passphrase-file "$PPNUL" \
        >"$T/s13.out" 2>"$T/s13.err"
    rc=$?
    if [ "$rc" = 0 ]; then
        fail "s13-nul-passphrase-refused (rc=0: the file was hashed)"
    elif ! grep -q 'NUL' "$T/s13.err"; then
        fail "s13-nul-passphrase-refused (message does not name the NUL: $(tr '\n' '|' < "$T/s13.err"))"
    else
        pass "s13-nul-passphrase-refused"
    fi
fi

# ------------------------------------- S14: an over-long passphrase line
# Catches: reading to EOF, so a file that is not a passphrase (a key file,
# a log, a binary) is hashed whole instead of being refused by size.
if [ ! -f "$S1STORE" ]; then
    skip "s14-oversize-passphrase-refused (no store from S1)"
else
    PPBIG="$T/pass-big"
    dd if=/dev/zero bs=5000 count=1 2>/dev/null | tr '\0' 'x' > "$PPBIG"
    printf '\n' >> "$PPBIG"
    chmod 600 "$PPBIG"
    "$TOOL" store list --store "$S1STORE" --passphrase-file "$PPBIG" \
        >"$T/s14.out" 2>"$T/s14.err"
    rc=$?
    if [ "$rc" = 0 ]; then
        fail "s14-oversize-passphrase-refused (rc=0: the file was hashed)"
    elif ! grep -q 'longer than' "$T/s14.err"; then
        fail "s14-oversize-passphrase-refused (message does not name the limit: $(tr '\n' '|' < "$T/s14.err"))"
    else
        pass "s14-oversize-passphrase-refused"
    fi
fi

echo "== VERDICT: FAIL=$FAIL =="
[ "$FAIL" = 0 ]
