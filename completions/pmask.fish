# fish completion for pmask.  Static file for the hand-written parser.

complete -c pmask -s l -l label -d 'Presentation label' -x
complete -c pmask -l label-empty -d 'Empty label'
complete -c pmask -l argv0 -d 'argv[0] of the program' -x
complete -c pmask -l comm -d 'Process name for top' -x
complete -c pmask -l keep-env -d 'Leave environ visible'
complete -c pmask -l env -d 'Add or replace one variable' -x
complete -c pmask -l env-file -d 'Read variables from a file' -r
complete -c pmask -l args-from-fd -d 'Read the command from a descriptor' -x
complete -c pmask -l on-exit -d 'Descendant policy' -x -a 'detach wait kill'
complete -c pmask -l no-follow -d 'Redact only the direct child'
complete -c pmask -l no-exit-kill -d 'Do not set PTRACE_O_EXITKILL'
complete -c pmask -l no-exitkill -d 'Alias for --no-exit-kill'
complete -c pmask -l no-dumpable -d 'Set PR_SET_DUMPABLE=0'
complete -c pmask -l no-new-privs -d 'Set no_new_privs'
complete -c pmask -l no-exact -d 'Keep the original cmdline byte extent'
complete -c pmask -l detach -d 'Detach each tracee after its exec; TracerPid reads 0'
complete -c pmask -l watch-rename -d 'Revert later renames to the label'
complete -c pmask -l rexec -d 'Exec from a sealed memfd'
complete -c pmask -l image -d 'Read the program bytes from PATH' -r
complete -c pmask -l image-from-fd -d 'Read the program bytes from a descriptor' -x
complete -c pmask -l exec-once -d 'Reuse one sealed image per distinct program'
complete -c pmask -l hugetlb -d 'Ask for a hugetlbfs-backed image'
complete -c pmask -l rexec-allow-disk -d 'Allow the on-disk last resort of --rexec'
complete -c pmask -l unshare -d 'New user, pid and mount namespaces'
complete -c pmask -l scope-name -d 'systemd transient scope name' -x
complete -c pmask -l daemon -d 'Run the job in a pmaskd' -r
complete -c pmask -l secret -d 'Deliver a secret on a descriptor: N=SRC' -x
complete -c pmask -l socket -d 'Secret-agent socket for agent: sources' -r
complete -c pmask -l isolate -d 'Fresh namespaces: pid,net,tmp | all | none' -x -a 'pid net tmp pid,net pid,tmp net,tmp pid,net,tmp all none'
complete -c pmask -l redact -d 'Ask for /proc redaction explicitly'
complete -c pmask -l no-redact -d 'Never touch /proc metadata'
complete -c pmask -l audit -d 'Print a residue row per tracee at each exec'
complete -c pmask -l report-file -d 'Write the --report document to PATH' -r
complete -c pmask -l report-fd -d 'Write the --report document to a descriptor' -x
complete -c pmask -l secret-fd-name -d 'Name the delivered secret memfd' -x
complete -c pmask -l memfd-name -d 'Name the image memfd' -x
complete -c pmask -l allow-argv-secret -d 'Keep a literal: or env: source and warn'
complete -c pmask -l secret-burn -d 'Seal without F_SEAL_SHRINK so the reader can truncate'
complete -c pmask -l secret-close-on-exec -d 'Close the descriptor in every descendant at its fork'
complete -c pmask -l report -d 'Output format' -x -a 'json text plain'
complete -c pmask -s q -l quiet -d 'Suppress diagnostics'
complete -c pmask -s v -l verbose -d 'Trace every event'
complete -c pmask -s V -l version -d 'Print version'
complete -c pmask -s h -l help -d 'Print help'
complete -c pmask -s a -d 'Alias for --label' -x
complete -c pmask -s E -d 'Alias for --keep-env'
complete -c pmask -s F -d 'Alias for --no-follow'
complete -c pmask -s K -d 'Alias for --no-exit-kill'
complete -c pmask -s f -d 'Accepted for compatibility, no effect'
complete -c pmask -s c -d 'Accepted for compatibility, no effect'
complete -c pmask -f -n 'test (count (commandline -opc)) -le 1' -a 'run\t"Run a command (same parser as the default mode)" store\t"The encrypted secret store" agent\t"Hold the store unlocked and serve it" get\t"Ask a running agent for one secret" read\t"Print a secret delivered to this process" probe\t"What this host allows" doctor\t"Store, agent and verdict in one report" help\t"Print help" version\t"Print version"'
