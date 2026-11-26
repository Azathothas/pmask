# fish completion for pmaskd.

complete -c pmaskd -s S -l socket -d 'Socket path' -r
complete -c pmaskd -s l -l label -d 'Default label' -x
complete -c pmaskd -s e -l env-file -d 'Environment file' -r
complete -c pmaskd -l no-inherit-env -d 'Jobs get the env-file only'
complete -c pmaskd -l keep-env -d 'Leave environ visible'
complete -c pmaskd -l allow-uid -d 'Accept this uid' -x
complete -c pmaskd -l run-as-uid -d 'Run jobs as client uid or explicit UID[:GID]'
complete -c pmaskd -l no-dumpable -d 'Force PR_SET_DUMPABLE=0 on jobs'
complete -c pmaskd -l allow-dumpable -d 'Keep jobs dumpable (PR_SET_DUMPABLE=1)'
complete -c pmaskd -l rexec -d 'Stage native ELF jobs from an executable carrier'
complete -c pmaskd -l no-rexec -d 'Disable default --rexec staging for ELF jobs'
complete -c pmaskd -l rexec-mode -d 'Image carrier for --rexec' -x -a 'auto path tmpfile memfd'
complete -c pmaskd -l socket-mode -d 'Socket permission bits' -x
complete -c pmaskd -l io-timeout -d 'Drop a stalled client' -x
complete -c pmaskd -l job-timeout -d 'Kill a job after this long' -x
complete -c pmaskd -l jobs -d 'Run up to N jobs at once' -x
complete -c pmaskd -l max-job-bytes -d 'Largest job argument bytes' -x
complete -c pmaskd -s q -l quiet -d 'Suppress diagnostics'
complete -c pmaskd -s v -l verbose -d 'Log each job'
complete -c pmaskd -s V -l version -d 'Print version'
complete -c pmaskd -s h -l help -d 'Print help'
