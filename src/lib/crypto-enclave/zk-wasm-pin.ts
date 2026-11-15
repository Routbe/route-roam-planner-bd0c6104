/**
 * SHA-384 of the committed anonymous booking engine (wasm/rout-zk, ABI 6:
 * BBS / Blind BBS, Pedersen + Bulletproofs, Poseidon SMT, forward-secure host
 * keys, slot credentials, window presentations and capacity pools, and the
 * hybrid ML-KEM-1024 + X25519 double ratchet with RVE2 envelopes)
 * (src/lib/crypto-enclave/wasm/rout-zk.wasm, embedded in zk-wasm-bytes.ts),
 * built deterministically by wasm/rout-zk/build.sh with the official rustup
 * rustc 1.95.0 (commit 59807616e, LLVM 22.1.2) and Cargo.lock; two builds in
 * fresh target directories gave the same bytes. The loader refuses any other
 * bytes before compiling; CI (.github/workflows/wasm-reproducible.yml) rebuilds
 * and compares. Rebuild only with build.sh and update this pin in the same change.
 */
export const ROUT_ZK_WASM_SHA384: string | null = "6f47f561133012e89ae585b3e632db40b488519facfbe453d3e72e8d003e1716c95f19e686238f255cc79b393e3980e4";
