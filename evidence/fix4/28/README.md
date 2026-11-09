# Issue 28 — `--hugetlb --image -` fails instead of falling back

## What was measured

Host: LXC container, Debian, uid 1000. `HugePages_Total` is 0 and
`HugePages_Free` is 0, so `memfd_create(MFD_HUGETLB)` succeeds but the
first write fails with `EINVAL`. Before the fix:

```
$ cat /bin/true | ./pmask --hugetlb --image -
pmask: -: Invalid argument (os error 22)      # exit 255
```

while `--hugetlb --image PATH` took the `fill_from` fallback and printed
`--hugetlb unavailable: ...; using an ordinary memfd`.

## What changed

`src/rexec.rs`:

- `prepare_fd` now fills the image through an ordinary memfd **spool**
  first, then moves the spool onto a huge memfd when `--hugetlb` asks for
  one. A refused huge memfd, or a write that fails part-way, falls back to
  the sealed spool and carries the note `--hugetlb unavailable: <cause>;
  using an ordinary memfd`.
- The spool is required rather than an `lseek` rewind: `--image -` and
  `--image-from-fd N` read a pipe or a socket, which cannot be read twice.
  A rewind-based retry would either duplicate bytes or lose them.
- `finish_hugetlb` is the one place that decision lives, so both carriers
  name the degradation identically. `seal_spool` closes the descriptor when
  the seal is refused, so the note path does not leak an fd.
- The cost is one extra copy of the image while a successful hugetlb run
  prepares; the note above the function says so.

## Evidence

- `qa28.log` — the raw commands and `tests/qa.d/28.sh`, all PASS.
- `negative-control.log` — the same fragment against the original
  `src/rexec.rs` (`git show 8bcfcb0^`): q28b, q28c, q28d and q28e FAIL with
  the issue's exact error.

## Unit test

`src/rexec.rs` `prepare_fd_falls_back_on_a_pipe_source`: writes the test
binary through a pipe (a writer thread, because a pipe holds 64 KiB), calls
`prepare_fd` with `Options { hugetlb: true }`, and asserts the image bytes
equal the source exactly and that the backing and note agree.

## Doc sentence (for the docs agent; do not edit `man/pmask.1` here)

> With `--hugetlb`, an image read from `--image -` or `--image-from-fd`
> falls back to an ordinary memfd exactly as `--image PATH` does: a host
> without free huge pages prints `--hugetlb unavailable: <reason>; using
> an ordinary memfd` and the run continues. `--hugetlb` never fails a run
> for lack of huge pages.

## What could not be tested

A host **with** free huge pages, where the spool-to-huge copy succeeds.
The branch is written and unit-tested only through the fallback arm; the
success arm is unexercised on this host. `vm/run.sh` was not run.
