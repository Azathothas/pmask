# fish completion for pmask.  Static file for the hand-written parser.

complete -c pmask -l profile -d 'Select execution and stealth profile' -x -a 'auto single tree tee compat'
complete -c pmask -l auto -d 'Alias for --profile auto (the default)'
complete -c pmask -l follow -d 'Follow and redact all descendants (tree mode)'
complete -c pmask -l no-rexec -d 'Opt out of profile-default --rexec image staging'
complete -c pmask -l rexec-mode -d 'Image carrier for --rexec' -x -a 'auto path memfd'
complete -c pmask -l cwd -d 'Change child working directory after resolving COMMAND' -r
complete -c pmask -l parent-label -d 'Separate presentation label for tree-mode supervisor' -x
complete -c pmask -l reparent -d 'Double-fork masked payload to PID 1 in single profile'
complete -c pmask -l allow-impersonation -d 'Allow kernel-thread [...] or critical-service labels'
complete -c pmask -l secret-fd -d 'Keep caller fd open across exec and export PMASK_SECRET_*' -x
complete -c pmask -l explain -d 'Print observer, capabilities, tradeoffs, and residuals'
complete -c pmask -l profile-json -d 'Emit versioned pmask-profile/1 JSON contract'
complete -c pmask -l pid -d 'Target PID for standalone --audit or --profile-json' -x
complete -c pmask -l observer -d 'Observer perspective for --audit' -x -a 'same-uid other-uid'
complete -c pmask -l json -d 'Emit JSON output for --audit, --explain, or --profile-json'
complete -c pmask -l token-env -d 'Env var holding secret token to hunt during --audit' -x
complete -c pmask -l token-fd -d 'File descriptor holding secret token to hunt during --audit' -x
complete -c pmask -l real-exe -d 'Expected real executable path to verify hidden in --audit' -r
complete -c pmask -l real-cwd -d 'Expected real working directory to verify hidden in --audit' -r
complete -c pmask -l allow-memfd -d 'Permit /memfd: exe paths in single-profile --audit'
complete -c pmask -s l -l label -d 'Presentation label' -x
complete -c pmask -l label-empty -d 'Empty label'
complete -c pmask -l argv0 -d 'argv[0] of the program' -x
complete -c pmask -l comm -d 'Process name for top' -x
complete -c pmask -l keep-env -d 'Leave environ visible (or --keep-env=NAME[,NAME...])'
complete -c pmask -l env -d 'Add or replace one variable' -x
complete -c pmask -l env-file -d 'Read variables from a file' -r
complete -c pmask -l args-from-fd -d 'Read the command from a descriptor' -x
complete -c pmask -l on-exit -d 'Descendant policy' -x -a 'detach wait kill'
complete -c pmask -l no-follow -d 'Redact only the direct child'
complete -c pmask -l no-exit-kill -d 'Do not set PTRACE_O_EXITKILL'
complete -c pmask -l no-exitkill -d 'Alias for --no-exit-kill'
complete -c pmask -l no-dumpable -d 'Set PR_SET_DUMPABLE=0'
complete -c pmask -l allow-dumpable -d 'Keep the payload dumpable (opt out of non-dumpable default)'
complete -c pmask -l strict-exec -d 'Refuse exec shapes that cannot be redacted at entry'
complete -c pmask -l allow-foreign -d 'Run a 32-bit image unredacted'
complete -c pmask -l stealth -d 'Compose the strongest tree shape and print the trade'
complete -c pmask -l hide-pid -d 'Hide the tree from same-uid /proc readers'
complete -c pmask -l encrypt-memory -d 'Seal at-rest copies (memfd_secret key) and mark block MADV_DONTDUMP'
complete -c pmask -l no-new-privs -d 'Set no_new_privs'
complete -c pmask -l no-exact -d 'Keep the original cmdline byte extent'
complete -c pmask -l detach -d 'Detach each tracee after its exec; TracerPid reads 0'
complete -c pmask -l watch-rename -d 'Revert later renames (use --watch-rename=strict for write traps)' -a 'strict'
complete -c pmask -l rexec -d 'Exec from a staged image or sealed memfd'
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
complete -c pmask -l audit -d 'Run standalone self/PID /proc audit or per-exec residue rows'
complete -c pmask -l report-file -d 'Write the --report document to PATH' -r
complete -c pmask -l report-fd -d 'Write the --report document to a descriptor' -x
complete -c pmask -l secret-fd-name -d 'Name the delivered secret memfd' -x
complete -c pmask -l memfd-name -d 'Name the image memfd' -x
complete -c pmask -l allow-argv-secret -d 'Keep a literal: or env: source and warn'
complete -c pmask -l secret-burn -d 'Seal without F_SEAL_SHRINK so the reader can truncate'
complete -c pmask -l secret-close-on-exec -d 'Close the descriptor in every descendant at its fork'
complete -c pmask -l report -d 'Output format (json only)' -x -a 'json'
complete -c pmask -s q -l quiet -d 'Suppress diagnostics'
complete -c pmask -s v -l verbose -d 'Trace every event'
complete -c pmask -s V -l version -d 'Print version'
complete -c pmask -s h -l help -d 'Print help (--help=all for full reference)'
complete -c pmask -s a -d 'Alias for --label' -x
complete -c pmask -s E -d 'Alias for --keep-env'
complete -c pmask -s F -d 'Alias for --no-follow'
complete -c pmask -s K -d 'Alias for --no-exit-kill'
complete -c pmask -s f -d 'Accepted for compatibility, no effect'
complete -c pmask -s c -d 'Accepted for compatibility, no effect'
complete -c pmask -f -n 'test (count (commandline -opc)) -le 1' -a 'run\t"Run a command (same parser as the default mode)" store\t"The encrypted secret store" agent\t"Hold the store unlocked and serve it" get\t"Ask a running agent for one secret" read\t"Print a secret delivered to this process" probe\t"What this host allows" doctor\t"Store, agent and verdict in one report" help\t"Print help" version\t"Print version"'
