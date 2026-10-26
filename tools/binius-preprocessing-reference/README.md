# Fixed Binius preprocessing reference

This package keeps the exact native experiment's host source, lockfile, three-file upstream patch and historical evidence without another vendor tree or binary artifact. `prepare.py` obtains source only from the committed Git object `115108d5a661d95c0b474b6ab02558bfe6c6bec7` in an existing local Binius64 repository. It never copies an uncommitted checkout. The commit tree must be `a1438c59bd15d013754247eeff104dcd7c7c2451`.

The historical native experiment accepted the retained 539,888-byte public-fixture proof and passed 12 checks. Those results are in `evidence/result.json`; their original filesystem paths and binary hashes are historical, not claims that this package has built in a new location. `evidence/historical-input-map.json` maps every historical source fingerprint to its packaged bytes. The complete 647-file vendor inventory is losslessly compressed in `evidence/provenance.json.gz`.

The fixed artifact is not bundled. A successful regeneration must produce exactly 2,714,051 bytes with SHA-256 `4d6fd19ea0092a261ed7041985b679ecad4b45f9cc6452a7a717979be7c35ef3`. The original manifest's relative `vendor/crates/...` paths are preserved by materializing the committed source into a fresh ignored `target/work-*/vendor` and copying the host files beside it.

Prepare and check source without building:

```sh
python3 prepare.py --upstream-git-dir /path/to/binius64 --prepare-only
```

Regenerate the fixed preprocessing using an already-installed Rust/Cargo **1.94.1**, locked dependencies and offline Cargo access:

```sh
python3 prepare.py --upstream-git-dir /path/to/binius64
```

Also verify the retained canonical fixture proof and all 12 checks:

```sh
python3 prepare.py --upstream-git-dir /path/to/binius64 --proof /path/to/proof.bin
```

`--proof` must match the historical public-fixture proof hash. Omitting it reports artifact regeneration only. `--cargo-target-dir /path/to/cache` optionally reuses Cargo artifacts; otherwise all generated material stays in this package's ignored `target`. The script uses `rustup run 1.94.1` and does not install a toolchain or fetch dependencies. The exact locked registry dependencies must already be cached. No proof, artifact, verifier key or expected-hash CLI argument can substitute for the pinned fixed parameters.

The script writes `target/reproduction.json` as `in_progress` before calling tools and writes `failed` for caught failures. It checks its source fingerprints and every prepared compilation input before and after external commands, validates the commit/tree and every upstream file hash, and checks all post-patch hashes. Patch application stops Git repository discovery at the fresh work directory, so installing this reference inside another repository cannot redirect its patch paths. Archive extraction accepts only expected bounded regular files; absolute paths, traversal, links, special files, duplicate files and mismatched content are rejected. Source is materialized into a new directory; existing work directories are preserved. Run the archive boundary checks separately with:

```sh
python3 prepare.py --selftest
```

`prepared_from_committed_objects_not_built` explicitly means no build occurred. A new successful build gets its own report, executable hash and functional results; it does not replace historical evidence. No status from this script approves quantum security, Soroban execution costs, on-chain recovery or account retirement. The separate portability probe maintains its own source and execution evidence. Upstream licensing and contribution instructions remain in the materialized committed source.
