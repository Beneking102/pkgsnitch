# Test fixtures

`demo-old` and `demo-new` are the raw sandbox output for versions 1.0.0 and
1.0.1 of the demo package in [`demo/`](../../demo): real `strace` output of
`npm rebuild` and of importing the package, plus the lockfile and manifest.

They were recorded by running the two phases under `strace` on Linux and then
rewriting the temporary directories of that run to the paths the sandbox
container uses (`/work` for the project, `/home/dev` for the home directory),
so the traces read exactly like a container run. Nothing else was edited.

`tests/pipeline.rs` feeds them to `pkgsnitch compare-dirs`, which runs the
whole analysis (parsing, behavior extraction, diffing, rating, rendering)
without needing a container runtime.
