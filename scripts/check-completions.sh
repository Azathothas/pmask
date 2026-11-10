#!/bin/sh
# Completion guard.
#
# `completions/` is a set of static tables for a hand-written parser, so
# nothing notices when the parser grows a flag.  The tables drift, and the
# drift is invisible until someone tabs at the wrong moment.  This script
# is the check that makes the drift impossible to merge:
#
#   1. every long option the parser accepts is offered by the completion;
#   2. every short option it accepts is offered too;
#   3. the completion offers nothing the parser would refuse.
#
# `src/cli.rs` is read, never modified: the option names are the quoted
# match arms of the parser.  `src/bin/pmaskd.rs` is read the same way for
# the daemon.
#
# Exit 0 when every table is complete, 1 on any gap, 2 on a setup error.
set -u
cd "$(dirname "$0")/.." || exit 2

FAIL=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }

TMP=$(mktemp -d 2>/dev/null) || TMP="/tmp/pmask-cc.$$"
mkdir -p "$TMP" || exit 2
trap 'rm -rf "$TMP"' EXIT

# long_options SRC -> option names without the leading --, one per line.
# Only the match arms of the hand-written parser match: an indented line
# that is a run of quoted literals followed by `=>`.  Error-message
# literals are not option names and do not match.
long_options() {
    awk '
        {
            head = $0
            p = index(head, "=>")
            if (!p) next
            head = substr(head, 1, p - 1)
            if (head !~ /^[ \t]*("[a-z][a-z0-9-]*"[ \t]*\|[ \t]*)*"[a-z][a-z0-9-]*"[ \t]*$/) next
            n = split(head, part, "\"")
            for (i = 2; i <= n; i += 2) {
                if (part[i] ~ /^[a-z][a-z0-9-]*$/) print part[i]
            }
        }
    ' "$1"
}

# short_options SRC -> single letters, one per line.
short_options() {
    awk '
        /^[ \t]*(b.[A-Za-z].([ \t]*\|[ \t]*)?)*b.[A-Za-z].[ \t]*=>/ {
            head = $0
            p = index(head, "=>")
            if (p) head = substr(head, 1, p - 1)
            while (match(head, /b\x27.\x27/)) {
                print substr(head, RSTART + 2, 1)
                head = substr(head, RSTART + RLENGTH)
            }
        }
    ' "$1"
}

# bash_table FILE -> every token of the `opts="..."` assignment, one per
# line, verbatim (`--label`, `-l`).  Only that assignment: a
# `case "$prev"` arm may name an option that the offered list forgot, and
# matching the whole file would hide exactly the defect this guard exists
# for.
bash_table() {
    awk '
        /^[ \t]*opts="/ { on = 1; sub(/^[^"]*"/, "") }
        on {
            done = ($0 ~ /"/)
            sub(/".*$/, "")
            print
            if (done) on = 0
        }
    ' "$1" | tr -s ' \t' '\n\n' | sed -n 's/^\(--*[A-Za-z0-9][A-Za-z0-9-]*\)$/\1/p'
}

# in_bash FILE NAME -> 0 when NAME is one of the tokens the table offers.
in_bash() {
    bash_table "$1" | grep -Fxq -- "$2"
}

# in_fish FILE NAME -> 0 when the fish table names the option.  A fish
# long option is `-l NAME`; a short one is `-s X`.
in_fish() {
    if [ "${2#--}" != "$2" ]; then
        grep -Eq -e "(^|[[:space:]])-l[[:space:]]+${2#--}([[:space:]]|$)" "$1"
    else
        grep -Eq -e "(^|[[:space:]])-s[[:space:]]+${2#-}([[:space:]]|$)" "$1"
    fi
}

# in_zsh FILE NAME -> 0 when the zsh table names the option.  The zsh
# spec puts the description in brackets straight after the name, so a
# word-boundary match is `--name[` or `--name]`.
in_zsh() {
    grep -Eq -e "(^|[^A-Za-z0-9_-])${2}([^A-Za-z0-9_-]|$)" "$1"
}

# ---------------------------------------------------------------- recovery
check_one() {
    # check_one LABEL PARSER COMPLETION KIND
    co_src=$2
    co_file=$3
    co_kind=$4
    co_label=$1
    if [ ! -f "$co_src" ]; then
        fail "$co_label-source-present ($co_src is missing)"
        return 0
    fi
    if [ ! -f "$co_file" ]; then
        fail "$co_label-completion-present ($co_file is missing)"
        return 0
    fi
    case "$co_kind" in
        long) list=$(long_options "$co_src") ;;
        short) list=$(short_options "$co_src") ;;
        *) echo "internal: bad kind $co_kind" >&2; exit 2 ;;
    esac
    if [ -z "$list" ]; then
        fail "$co_label-extracted-from-the-parser (no $co_kind option found in $co_src)"
        return 0
    fi
    n=0
    missing=""
    for opt in $list; do
        n=$((n + 1))
        case "$co_kind" in
            long) name="--$opt" ;;
            short) name="-$opt" ;;
        esac
        case "$(basename "$co_file")" in
            *.fish) in_fish "$co_file" "$name" || missing="$missing $name" ;;
            _*) in_zsh "$co_file" "$name" || missing="$missing $name" ;;
            *) in_bash "$co_file" "$name" || missing="$missing $name" ;;
        esac
    done
    if [ -z "$missing" ]; then
        pass "$co_label-all-$n-$co_kind-options-are-offered"
    else
        fail "$co_label-missing-$co_kind-options:$missing"
        for m in $missing; do
            echo "       absent from $co_file: $m"
        done
    fi
}

# The extracted count is a shape match, so a parser refactor can leave the
# extraction yielding one option and every table agreeing with that one.
# The floor makes a collapsed extraction a failure, not a pass.
check_floor() {
    cf_label=$1
    cf_src=$2
    cf_min=$3
    if [ ! -f "$cf_src" ]; then
        return 0
    fi
    cf_n=$(long_options "$cf_src" | grep -c .)
    if [ "$cf_n" -ge "$cf_min" ]; then
        pass "$cf_label-long-option-floor ($cf_n found, floor $cf_min)"
    else
        fail "$cf_label-long-option-floor ($cf_n found, want >= $cf_min: the extraction or the parser lost options)"
    fi
}

# The reverse direction: a table that offers an option the parser refuses
# is a completion that suggests a usage error.
check_reverse_bash() {
    cr_src=$1
    cr_file=$2
    cr_label=$3
    if [ ! -f "$cr_src" ] || [ ! -f "$cr_file" ]; then
        return 0
    fi
    long_options "$cr_src" > "$TMP/parser-long.txt"
    short_options "$cr_src" > "$TMP/parser-short.txt"
    extra=""
    for tok in $(bash_table "$cr_file"); do
        case "$tok" in
            --*) grep -Fxq -- "${tok#--}" "$TMP/parser-long.txt" || extra="$extra $tok" ;;
            -*) grep -Fxq -- "${tok#-}" "$TMP/parser-short.txt" || extra="$extra $tok" ;;
        esac
    done
    if [ -z "$extra" ]; then
        pass "$cr_label-offers-nothing-the-parser-refuses"
    else
        fail "$cr_label-offers-options-the-parser-refuses:$extra"
    fi
}

# --------------------------------------------------------------- pmask
check_floor pmask src/cli.rs 40
for f in completions/pmask.bash completions/pmask.fish completions/_pmask; do
    check_one "pmask-$(basename "$f")" src/cli.rs "$f" long
done
check_one "pmask-pmask.bash" src/cli.rs completions/pmask.bash short
check_reverse_bash src/cli.rs completions/pmask.bash pmask-pmask.bash

# --------------------------------------------------------------- pmaskd
check_floor pmaskd src/bin/pmaskd.rs 12
for f in completions/pmaskd.bash completions/pmaskd.fish completions/_pmaskd; do
    check_one "pmaskd-$(basename "$f")" src/bin/pmaskd.rs "$f" long
done
check_one "pmaskd-pmaskd.bash" src/bin/pmaskd.rs completions/pmaskd.bash short
check_reverse_bash src/bin/pmaskd.rs completions/pmaskd.bash pmaskd-pmaskd.bash

# ------------------------------------------------------- syntax of the tables
# A complete table with a syntax error completes nothing.  bash is the
# one shell the CI image always has; a shell that is absent is a SKIP, not
# a pass.
if command -v bash >/dev/null 2>&1; then
    for f in completions/pmask.bash completions/pmaskd.bash; do
        if bash -n "$f" 2>"$TMP/syn.err"; then
            pass "syntax-$(basename "$f")"
        else
            fail "syntax-$(basename "$f") ($(tr '\n' '|' < "$TMP/syn.err"))"
        fi
    done
else
    echo "SKIP syntax-bash-tables (no bash on this host)"
fi

# ------------------------------------------------------- value lists
# `--report` is the one option whose value list is both small and a
# documented contract: only `json` does anything (issue #36 -- `text` and
# `plain` were accepted and did nothing).  A table that offers the dead
# spellings is a completion that suggests a no-op.
for f in completions/pmask.bash completions/pmask.fish completions/_pmask; do
    [ -f "$f" ] || continue
    case "$(basename "$f")" in
        *.bash)
            got=$(sed -n '/--report)/,/;;/p' "$f" | grep -o 'compgen -W "[^"]*"' | sed 's/.*"\(.*\)"/\1/')
            ;;
        *.fish)
            got=$(sed -n "s/.*-l report .*-a '\([^']*\)'.*/\1/p" "$f")
            ;;
        *)
            got=$(sed -n "s/.*--report\[[^]]*\]:format:(\([^)]*\)).*/\1/p" "$f")
            ;;
    esac
    if [ "$got" = "json" ]; then
        pass "pmask-$(basename "$f")-report-offers-json-only"
    else
        fail "pmask-$(basename "$f")-report-offers-json-only (offers [${got}])"
    fi
done

echo "== COMPLETIONS: FAIL=$FAIL =="
[ "$FAIL" = 0 ]
