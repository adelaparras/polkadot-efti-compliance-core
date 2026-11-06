# Polkadot Substrate eFTI Compliance Pallet Specification

## Pallet Architecture
- **`pallet-efti`**: Validates EU Regulation 2020/1056 transport data exchange format.
- **`pallet-eidas`**: Anchors X.509 eIDAS Qualified Electronic Certificates on-chain.
- **`pallet-mletr`**: UNCITRAL Model Law on Electronic Transferable Records primitives.

## Rust Safety & Benchmarks
- `#[pallet::weight]` annotations derived from Substrate benchmarking framework.
- Zero-panic arithmetic using `saturating_add` and `checked_mul`.
