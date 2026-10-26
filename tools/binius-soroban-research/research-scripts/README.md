# Research scripts

`wasm_sections.py` reports the byte size of every section of one or more
compiled WebAssembly modules, using only the Python standard library. It
produced the section comparison recorded in
`docs/sdk-code-size-breakdown.json`.

Reproduce, from the repository root, after building both modules:

```sh
python3 -I tools/binius-soroban-research/research-scripts/wasm_sections.py \
  tools/binius-verifier-next/target/bin/qasset_binius_external_input.optimized.wasm \
  tools/binius-soroban-research/target/artifacts/qasset_binius_soroban_compact.optimized.wasm
```

The SHA-256 of each input module is recorded in the evidence file; compare
them before trusting a rerun, since a rebuilt module with different bytes
will report different sizes.
