# Issue 31 — `--args-from-fd 0` closes the payload's stdin

## What was measured

```
$ printf '/bin/sh\0-c\0ls -l /proc/self/fd/0\0' | ./pmask -q --args-from-fd 0
ls: cannot access '/proc/self/fd/0': No such file or directory
```

The payload's fd 0 was closed. With the vector on fd 3 instead, the same
payload printed a `pipe:` link, so the read was fine and the close was the
`File::from_raw_fd` drop.

## What changed

`src/cli.rs`, `Cli::load_args_fd` only:

- The caller's descriptor is duplicated with `F_DUPFD_CLOEXEC` (above the
  stdio range) and the `File` wraps the *duplicate*. The caller's fd is
  untouched, so `--args-from-fd 0` leaves the payload's fd 0 open and the
  vector read advances its offset to end of file.
- A refused `dup` is a hard error naming the descriptor and the errno,
  instead of a silent run with no arguments.
- The doc comment says the source is consumed: the descriptor reaches end
  of file and the payload sees it there.

`--image-from-fd` needed no change: `prepare_fd` never wrapped the caller's
descriptor in an owning type. `src/secret.rs:785`, `src/daemon.rs:576`,
`src/daemon.rs:1402` and `src/agent.rs:771,825` wrap descriptors those
functions opened themselves or deliberately take ownership of a delivered
secret descriptor; none of them is a caller's descriptor that must survive.

## Evidence

- `qa31.log` — the raw command and `tests/qa.d/31.sh`, all PASS.
- `negative-control.log` — the same fragment against the original
  `src/cli.rs` (`git show f314d9b^`): q31b and q31c FAIL.

## Doc sentence (for the docs agent; do not edit `man/pmask.1` here)

> `--args-from-fd N` consumes the descriptor: it is read to end of file and
> left open. With `N` = 0 the payload's standard input sits at end of file
> afterwards, so a payload that reads from stdin sees EOF rather than
> `EBADF`. Pass the vector on a separate descriptor (for example
> `3<args.bin`) when the payload also needs stdin.

## What could not be tested

Nothing was blocked. `--args-from-fd` with a vector larger than 8 MiB is
covered by `tests/options.sh` O23, which was run and passed; that path now
takes the error branch *after* the dup, so the descriptor is closed by the
`File` drop before `die()` and no fd is leaked on the failure path either.
