# bash completion for pmask                       -*- shell-script -*-
# Static file: the option parser is hand-written, so the list is too.

_pmask() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    opts="--profile --auto --follow --no-rexec --rexec-mode --cwd \
--parent-label --reparent --allow-impersonation --secret-fd \
--explain --profile-json --pid --observer --json --token-env --token-fd \
--real-exe --real-cwd --allow-memfd \
-l --label --label-empty --argv0 --comm --keep-env --env --env-file \
--args-from-fd --on-exit --no-follow --no-exit-kill --no-exitkill \
--no-dumpable --allow-dumpable --strict-exec --allow-foreign --stealth \
--hide-pid --encrypt-memory --no-new-privs --no-exact --detach \
--watch-rename --rexec --unshare --image --image-from-fd --exec-once \
--hugetlb --rexec-allow-disk --scope-name --daemon --secret --socket \
--isolate --redact --no-redact --audit --allow-argv-secret --secret-burn \
--secret-close-on-exec --report --report-file --report-fd \
--secret-fd-name --memfd-name \
-q --quiet -v --verbose -V --version -h --help --help-all -a -E -F -K -f -c"

    if [ "$COMP_CWORD" -eq 1 ] && [[ "$cur" != -* ]]; then
        COMPREPLY=( $(compgen -W "run store agent get read probe doctor help version" -- "$cur") )
        return 0
    fi

    case "$prev" in
        --profile)
            COMPREPLY=( $(compgen -W "auto single tree tee compat" -- "$cur") )
            return 0
            ;;
        --rexec-mode)
            COMPREPLY=( $(compgen -W "auto path tmpfile memfd" -- "$cur") )
            return 0
            ;;
        --observer)
            COMPREPLY=( $(compgen -W "same-uid other-uid" -- "$cur") )
            return 0
            ;;
        --cwd|--real-cwd)
            COMPREPLY=( $(compgen -d -- "$cur") )
            return 0
            ;;
        -l|--label|-a|--argv0|--comm|--parent-label|--scope-name)
            COMPREPLY=( $(compgen -W "ci-runner app-worker" -- "$cur") )
            return 0
            ;;
        --daemon|--env-file|--secret|--socket|--image|--report-file|--real-exe)
            COMPREPLY=( $(compgen -f -- "$cur") )
            return 0
            ;;
        --image-from-fd|--args-from-fd|--secret-fd|--report-fd|--token-fd|--pid|--token-env)
            COMPREPLY=()
            return 0
            ;;
        --on-exit)
            COMPREPLY=( $(compgen -W "detach wait kill" -- "$cur") )
            return 0
            ;;
        --report)
            # Only `json` is documented and only `json` is meaningful: the
            # other two spellings were accepted and did nothing (issue #36).
            COMPREPLY=( $(compgen -W "json" -- "$cur") )
            return 0
            ;;
        --env)
            COMPREPLY=( $(compgen -W "PATH= HOME= LANG=" -- "$cur") )
            return 0
            ;;
    esac

    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
        return 0
    fi
    COMPREPLY=( $(compgen -c -- "$cur") )
}
complete -F _pmask pmask
