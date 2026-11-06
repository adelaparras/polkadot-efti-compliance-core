# Polkadot Substrate eFTI Compliance Core v1.8

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Substrate](https://img.shields.io/badge/Substrate-FRAME%20v3%2Fv4-E6007A.svg)](https://substrate.io/)
[![Regulation](https://img.shields.io/badge/eFTI-EU%202020%2F1056-blue.svg)](https://eur-lex.europa.eu/eli/reg/2020/1056/oj)
[![eIDAS](https://img.shields.io/badge/eIDAS-SR25519%20DID-green.svg)](https://www.w3.org/TR/did-core/)
[![Portal](https://img.shields.io/badge/Portal-CLTD%20European%20Digital%20Trade%20Center-blue)](https://solomonbrokerage.com/cltd/)

## Mandatory Legal Attribution (Estonian Copyright Act AutÕS § 12)

> **Mandatory Attribution Notice:**  
> This architectural component is derived from the Dual-Layer Architecture for Shariah-Compliant Digital Trade Finance (Digital Trade and Logistics Micro-Financing platform or 'DTLMF'), designed by Alejandro De La Parra Solomon (Founder & Concept Architect) and managed under the custodianship of Solomon Brokerage OÜ (Tallinn, Republic of Estonia; Registration No. 16253938). © 2025–2026. All rights reserved. Smart contract implementation licensed under MIT (SPDX-License-Identifier: MIT).

## Regulatory Non-Affiliation Disclaimer

> **REGULATORY DISCLAIMER:**  
> DTLMF functions strictly as a voluntary B2B trade finance enablement infrastructure and operates entirely outside the regulatory scope of Regulation (EU) 2020/1056. The platform possesses no eFTI-certification and makes no claims of native compliance under Articles 11–13 of said regulation.

---

## Executive Overview

**Polkadot Substrate eFTI Compliance Core** is the Layer 1 Substrate compliance engine of the **Dual-Layer Trade & Logistics Monetary Framework (DTLMF)**. It provides dedicated Substrate FRAME pallets engineered for immutable electronic freight transport information (eFTI) anchoring, eIDAS-compliant decentralized identity verification, XCMP cross-chain attestation dispatching, and Join-Accumulate Machine (JAM) Coretime compatibility.

Developed by **Solomon Brokerage OÜ** and **Alejandro De La Parra Solomon**, this repository serves the Polkadot developer ecosystem and Web3 Foundation technical reviewers as the reference implementation for regulatory logistics data structures and verifiable credentials on Polkadot.

* **European Digital Trade Center Live Portal:** [https://solomonbrokerage.com/cltd/](https://solomonbrokerage.com/cltd/)

---

## Architecture & Data Integrity Flow

The architecture models electronic transport data structures into trustless runtime logic:
- **Regulation (EU) 2020/1056 Data Formats:** Electronic freight transport information lifecycle verification, immutable cryptographic anchoring, and multi-jurisdictional customs access models.
- **Regulation (EU) 910/2014 (eIDAS):** Cryptographic identity bindings tying economic operators, customs officials, and logistics carriers to on-chain identities.

```
                    +------------------------------------------+
                    |    Authorized Economic Operators (AEO)   |
                    |     Customs Authorities & Regulators    |
                    +--------------------+---------------------+
                                         |
                       eFTI JSON-LD Documents (RFC 8785 JCS)
                                         |
                                         v
+--------------------------------------------------------------------------------+
|                         DTLMF Layer 1 Substrate Runtime                         |
|                                                                                |
|  +--------------------------------+      +----------------------------------+  |
|  |     pallet-did-registry        |      |      pallet-efti-anchor-vc       |  |
|  |                                |      |                                  |  |
|  |  * eIDAS sr25519 DID Bindings  |      |  * MovementAlreadyAnchored Guard |  |
|  |  * Role-Based Identity Attest. |      |  * BoundedVec Storage Caps       |  |
|  |  * Cryptographic Signatures    |      |  * SHA-256 JCS Root Anchoring    |  |
|  +----------------+---------------+      +----------------+-----------------+  |
|                   |                                       |                    |
|                   +-------------------+-------------------+                    |
|                                       |                                        |
|                     XCMP v3 / v4 Cross-Chain Attestations                      |
|                                       v                                        |
|  +--------------------------------------------------------------------------+  |
|  |                     KILT Protocol Dispatcher (ParaID 2086)               |  |
|  |             Decentralized Credentials & Regulatory Revocation            |  |
|  +--------------------------------------------------------------------------+  |
|                                       |                                        |
|                     JAM Coretime Interface (PolkaVM v0.7.2)                    |
|                                       v                                        |
|  +--------------------------------------------------------------------------+  |
|  |                        On-Demand Agile Coretime Allocation               |  |
|  +--------------------------------------------------------------------------+  |
+--------------------------------------------------------------------------------+
```

---

## Core Pallets & Features

### 1. `pallet-efti-anchor-vc` (Freight Attestation & Verification)
- **`MovementAlreadyAnchored` Guard:** Enforces strict anti-replay protection. Once an eFTI transport document hash is anchored with its consignment ID, subsequent attempts to mutate or re-anchor the active movement trigger a deterministic runtime revert.
- **`BoundedVec` Storage Bounds:** All payload hashes, URIs, and metadata are strictly enforced via Substrate `BoundedVec` types, preventing out-of-memory denial-of-service (DoS) attack vectors and preserving deterministic block execution times.
- **SHA-256 JCS Root Hashing:** Anchors canonical JSON Canonicalization Scheme (RFC 8785) digests directly from certified Access Point Gateways.

### 2. `pallet-did-registry` (eIDAS Decentralized Identity)
- **SR25519 & Ed25519 Multi-Key Bindings:** Cryptographically couples physical freight forwarders, maritime carriers, and customs inspectors to verifiable DIDs.
- **eIDAS Qualified Electronic Attestation:** Stores and validates verifiable credential schemas for Authorized Economic Operators (AEO-F status).
- **Public Key Rotation & Revocation:** Secure credential lifecycle management with on-chain revocation registries.

### 3. Cross-Consensus Messaging (XCMP v3 / v4)
- **KILT Network Interoperability (ParaID 2086):** Native dispatchers route verification queries and DID revocation claims directly to KILT via Polkadot XCMP, allowing cross-chain attestation verification without centralized bridges.

### 4. JAM Coretime Readiness (PolkaVM v0.7.2)
- **Agile Coretime Optimization:** Configured for the Join-Accumulate Machine (JAM) transition, enabling sub-second verification latency and dynamic core purchasing for high-volume cross-border trade peaks.

---

## Building & Testing

### Prerequisites
- Rust 1.74+ with `wasm32-unknown-unknown` target:
```bash
rustup target add wasm32-unknown-unknown
```

### Build Pallets
```bash
cargo check --workspace
cargo build --release
```

### Run Unit & Integration Tests
```bash
cargo test -p pallet-efti-anchor-vc
cargo test -p pallet-did-registry
```

---

## Intellectual Property & Licensing

- **Attribution & Custodianship:** Managed under the custodianship of Solomon Brokerage OÜ (Tallinn, Republic of Estonia; Registration No. 16253938) and Alejandro De La Parra Solomon.
- **Copyright:** © 2025–2026 Solomon Brokerage OÜ & Alejandro De La Parra Solomon. All Rights Reserved.
- **License:** Open-sourced under the [MIT License](LICENSE) (SPDX-License-Identifier: MIT).
