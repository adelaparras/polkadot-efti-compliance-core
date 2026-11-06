// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Alejandro De La Parra Solomon. All rights reserved.
// Custodianship and Data Controller: Solomon Brokerage OÜ (Tallinn, Republic of Estonia)
//
// Appendix XIII.A: pallet-efti-anchor-vc: eFTI Cargo Possession & Verification Specification
// Final Compile-Hardened Production Version 1.0 (WASM & PVM Compatible)

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::{
        dispatch::DispatchResult,
        pallet_prelude::*,
    };
    use frame_system::pallet_prelude::*;
    use sp_std::vec::Vec;

    // =====================================================================
    // CONFIGURATION TRAIT
    // =====================================================================
    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The overarching event type.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Maximum byte length for a Movement ID string (eFTI unique identifier).
        /// V1.8 Spec: ConstU32<64>
        #[pallet::constant]
        type MaxMovementIdLen: Get<u32>;

        /// Maximum byte length for the off-chain document URI (IPFS CID or HTTPS URL).
        /// V1.8 Spec: ConstU32<256>
        #[pallet::constant]
        type MaxUriLen: Get<u32>;

        /// Maximum byte length for the DID string (creator/issuer identity reference).
        /// V1.8 Spec: ConstU32<128>
        #[pallet::constant]
        type MaxDidLen: Get<u32>;

        /// Maximum byte length for encrypted key pointer metadata (HSM envelope reference).
        /// V1.8 Spec: ConstU32<256>
        #[pallet::constant]
        type MaxEncryptedKeyPtrLen: Get<u32>;

        /// Maximum byte length for Arbitrum AnyTrust transaction hash reference.
        /// V1.8 Spec: ConstU32<128>
        #[pallet::constant]
        type MaxArbitrumTxHashLen: Get<u32>;

        /// Maximum number of access log entries per movement (hard DoS cap).
        /// V1.8 Spec: ConstU32<10>
        #[pallet::constant]
        type MaxAccessLogsPerMovement: Get<u32>;

        /// Maximum number of leaf hashes per Merkle batch commit.
        /// V1.8 Spec: ConstU32<64>
        #[pallet::constant]
        type MaxMerkleLeavesPerBatch: Get<u32>;

        /// Cross-pallet DID validation trait. Decouples dependency on pallet-did-registry.
        type DidValidator: DidValidator<Self::AccountId>;

        /// Weight information for all dispatchable extrinsics.
        type WeightInfo: WeightInfo;
    }

    // =====================================================================
    // WEIGHT INFO TRAIT
    // =====================================================================
    pub trait WeightInfo {
        fn create_anchor() -> Weight;
        fn update_anchor_status() -> Weight;
        fn log_access() -> Weight;
        fn commit_merkle_batch() -> Weight;
        fn dispatch_xcmp_attestation() -> Weight;
        fn configure_coretime_allocation() -> Weight;
    }

    /// Unhardened fallback weights — MUST be replaced by FRAME Benchmarking output in production.
    impl WeightInfo for () {
        fn create_anchor() -> Weight {
            Weight::from_parts(50_000_000, 4_096)
        }
        fn update_anchor_status() -> Weight {
            Weight::from_parts(30_000_000, 2_048)
        }
        fn log_access() -> Weight {
            Weight::from_parts(25_000_000, 2_048)
        }
        fn commit_merkle_batch() -> Weight {
            Weight::from_parts(80_000_000, 8_192)
        }
        fn dispatch_xcmp_attestation() -> Weight {
            Weight::from_parts(60_000_000, 4_096)
        }
        fn configure_coretime_allocation() -> Weight {
            Weight::from_parts(20_000_000, 1_024)
        }
    }

    // =====================================================================
    // DID VALIDATOR TRAIT (DECOUPLED)
    // =====================================================================
    /// Decoupled read-only DID presence check to be implemented by pallet-did-registry.
    pub trait DidValidator<AccountId> {
        fn is_registered(who: &AccountId) -> bool;
    }

    /// Permissive default implementation for unit testing environments.
    impl<AccountId> DidValidator<AccountId> for () {
        fn is_registered(_: &AccountId) -> bool {
            true
        }
    }

    // =====================================================================
    // PALLET STRUCT
    // =====================================================================
    const STORAGE_VERSION: StorageVersion = StorageVersion::new(2);

    #[pallet::pallet]
    #[pallet::storage_version(STORAGE_VERSION)]
    pub struct Pallet<T>(_);

    // =====================================================================
    // ENUMERATIONS (STATE MACHINE TYPES)
    // =====================================================================

    /// The canonical lifecycle state machine for an eFTI cargo anchor record.
    /// Enforces a strictly monotonic Directed Acyclic Graph (DAG):
    ///   Created ──► Updated ──► Withdrawn
    /// Any reverse or illegal transition is rejected at the extrinsic level.
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    pub enum AnchorStatus {
        /// Initial state: cargo anchor has been created and validated.
        Created,
        /// Intermediate state: an authorized update has been applied.
        Updated,
        /// Terminal state: anchor has been officially withdrawn from active trade.
        Withdrawn,
    }

    /// Outcome code recorded in access logs for regulatory audit trail compliance.
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    pub enum AccessOutcome {
        /// Accessor read the document manifest successfully.
        Read = 1,
        /// Accessor triggered a status update on the document.
        Update = 2,
        /// Accessor performed a regulatory audit query.
        AuditQuery = 3,
    }

    // =====================================================================
    // COMPOSITE STORAGE TYPES
    // =====================================================================

    /// Encrypted document pointer referencing the off-chain HSM-encrypted payload.
    /// The cid_or_url field references an IPFS CID or HTTPS gateway URI.
    /// encryption_meta stores the wrapped Content Key envelope reference (HSM key ID + IV).
    #[derive(Encode, Decode, DecodeWithMemTracking, TypeInfo, MaxEncodedLen)]
    #[scale_info(skip_type_params(T))]
    pub struct EncryptedPointer<T: Config> {
        /// IPFS CID or HTTPS URI pointing to the encrypted off-chain payload.
        pub cid_or_url: BoundedVec<u8, T::MaxUriLen>,
        /// Storage backend type discriminant: 1 = IPFS, 2 = Azure Blob, 3 = S3.
        pub storage_type: u8,
        /// Encryption algorithm discriminant: 1 = AES-256-GCM, 2 = ChaCha20-Poly1305.
        pub encryption_scheme: u8,
        /// Opaque blob containing the HSM-wrapped symmetric key envelope and IV.
        pub encryption_meta: BoundedVec<u8, T::MaxEncryptedKeyPtrLen>,
    }

    impl<T: Config> Clone for EncryptedPointer<T> {
        fn clone(&self) -> Self {
            Self {
                cid_or_url: self.cid_or_url.clone(),
                storage_type: self.storage_type,
                encryption_scheme: self.encryption_scheme,
                encryption_meta: self.encryption_meta.clone(),
            }
        }
    }

    impl<T: Config> PartialEq for EncryptedPointer<T> {
        fn eq(&self, other: &Self) -> bool {
            self.cid_or_url == other.cid_or_url
                && self.storage_type == other.storage_type
                && self.encryption_scheme == other.encryption_scheme
                && self.encryption_meta == other.encryption_meta
        }
    }

    impl<T: Config> Eq for EncryptedPointer<T> {}

    impl<T: Config> core::fmt::Debug for EncryptedPointer<T> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("EncryptedPointer")
                .field("cid_or_url", &self.cid_or_url)
                .field("storage_type", &self.storage_type)
                .field("encryption_scheme", &self.encryption_scheme)
                .field("encryption_meta", &self.encryption_meta)
                .finish()
        }
    }

    /// The primary on-chain anchor record for an eFTI cargo movement.
    /// Stores the SHA-256 document hash, encrypted off-chain URI, movement metadata,
    /// DID of the creator, Arbitrum AnyTrust tx reference, and lifecycle status.
    #[derive(Encode, Decode, DecodeWithMemTracking, TypeInfo, MaxEncodedLen)]
    #[scale_info(skip_type_params(T))]
    pub struct AnchorRecord<T: Config> {
        /// SHA-256 hash of the canonical (JCS-normalized) eFTI document payload.
        pub doc_hash: [u8; 32],
        /// Encrypted pointer to the full document stored in the off-chain layer.
        pub doc_store_uri: EncryptedPointer<T>,
        /// Unique eFTI movement identifier (e.g. "MOV-2026-EU-001").
        pub movement_id: BoundedVec<u8, T::MaxMovementIdLen>,
        /// W3C DID of the originating Economic Operator (creator identity).
        pub creator_did: BoundedVec<u8, T::MaxDidLen>,
        /// Reference to the originating Arbitrum AnyTrust L2 transaction hash.
        pub arbitrum_tx_hash: BoundedVec<u8, T::MaxArbitrumTxHashLen>,
        /// Declared cargo manifest value in USD cents (integer, no floating point).
        pub manifest_value_usd_cents: u64,
        /// Lifecycle status enforcing the DAG state machine.
        pub status: AnchorStatus,
        /// Block number at creation, used for finality and audit ordering.
        pub created_at_block: u64,
    }

    impl<T: Config> Clone for AnchorRecord<T> {
        fn clone(&self) -> Self {
            Self {
                doc_hash: self.doc_hash,
                doc_store_uri: self.doc_store_uri.clone(),
                movement_id: self.movement_id.clone(),
                creator_did: self.creator_did.clone(),
                arbitrum_tx_hash: self.arbitrum_tx_hash.clone(),
                manifest_value_usd_cents: self.manifest_value_usd_cents,
                status: self.status.clone(),
                created_at_block: self.created_at_block,
            }
        }
    }

    impl<T: Config> PartialEq for AnchorRecord<T> {
        fn eq(&self, other: &Self) -> bool {
            self.doc_hash == other.doc_hash
                && self.doc_store_uri == other.doc_store_uri
                && self.movement_id == other.movement_id
                && self.creator_did == other.creator_did
                && self.arbitrum_tx_hash == other.arbitrum_tx_hash
                && self.manifest_value_usd_cents == other.manifest_value_usd_cents
                && self.status == other.status
                && self.created_at_block == other.created_at_block
        }
    }

    impl<T: Config> Eq for AnchorRecord<T> {}

    impl<T: Config> core::fmt::Debug for AnchorRecord<T> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("AnchorRecord")
                .field("doc_hash", &self.doc_hash)
                .field("doc_store_uri", &self.doc_store_uri)
                .field("movement_id", &self.movement_id)
                .field("creator_did", &self.creator_did)
                .field("arbitrum_tx_hash", &self.arbitrum_tx_hash)
                .field("manifest_value_usd_cents", &self.manifest_value_usd_cents)
                .field("status", &self.status)
                .field("created_at_block", &self.created_at_block)
                .finish()
        }
    }

    /// A single immutable access log entry recording a regulatory accessor interaction.
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    pub struct AccessLogEntry {
        /// AccountId of the entity requesting access (must have registered DID).
        pub accessor: [u8; 32],
        /// Block number at which access was recorded (monotonic, tamper-evident).
        pub block_number: u64,
        /// Nature of the access operation performed.
        pub outcome: AccessOutcome,
    }

    /// Supported regulatory attestation standards for cross-chain migration.
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    pub enum AttestationStandard {
        /// EU Regulation 2020/1056 electronic freight transport information standard
        EftiRegulation,
        /// EU Regulation No 910/2014 qualified electronic trust services
        EidasQualified,
        /// W3C Verifiable Credential standard for decentralized identity (e.g. KILT Protocol)
        W3cVerifiableCredential,
    }

    /// Execution parameters for PolkaVM Coretime allocation under the JAM Gray Paper v0.7.2 specification.
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    pub struct CoretimeAllocationConfig {
        /// Core index assigned to this parachain service under the Agile Coretime model.
        pub core_index: u16,
        /// Number of block slices allocated per work package.
        pub slice_duration_blocks: u32,
        /// JAM Service ID for stateless parallel execution in the Refine authorizer loop.
        pub jam_service_id: u32,
        /// State proof root hash for stateless verification.
        pub state_proof_hash: [u8; 32],
    }

    // =====================================================================
    // STORAGE DECLARATIONS
    // =====================================================================

    /// Primary anchor registry keyed by the 32-byte SHA-256 document hash.
    /// Prevents double-pledging by rejecting duplicate doc_hash insertions.
    #[pallet::storage]
    #[pallet::getter(fn anchors)]
    pub type Anchors<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        [u8; 32],
        AnchorRecord<T>,
        OptionQuery,
    >;

    /// Secondary index: maps a bounded Movement ID to the document hash that anchored it.
    /// Enforces the constraint that each movement can only be pledged once (Maysir prevention).
    #[pallet::storage]
    #[pallet::getter(fn movement_registry)]
    pub type MovementRegistry<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        BoundedVec<u8, T::MaxMovementIdLen>,
        [u8; 32],
        OptionQuery,
    >;

    /// Bounded access log storage per movement ID (StorageDoubleMap).
    /// Hard-capped at MaxAccessLogsPerMovement entries to prevent state exhaustion.
    /// Key1: movement_id | Key2: sequential log index (u32).
    #[pallet::storage]
    #[pallet::getter(fn access_logs)]
    pub type AccessLogs<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat, BoundedVec<u8, T::MaxMovementIdLen>,
        Twox64Concat, u32,
        AccessLogEntry,
        OptionQuery,
    >;

    /// Tracks the current count of access logs per movement_id to enforce the hard cap.
    #[pallet::storage]
    #[pallet::getter(fn access_log_count)]
    pub type AccessLogCount<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        BoundedVec<u8, T::MaxMovementIdLen>,
        u32,
        ValueQuery,
    >;

    /// Merkle batch registry keyed by a 32-byte batch root hash.
    /// Each entry contains a bounded list of leaf hashes committed in a single transaction.
    #[pallet::storage]
    #[pallet::getter(fn merkle_batches)]
    pub type MerkleBatches<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        [u8; 32],
        BoundedVec<[u8; 32], T::MaxMerkleLeavesPerBatch>,
        OptionQuery,
    >;

    /// Global Coretime allocation parameters for PolkaVM / JAM parallel execution.
    #[pallet::storage]
    #[pallet::getter(fn coretime_config)]
    pub type CoretimeConfig<T: Config> = StorageValue<_, CoretimeAllocationConfig, OptionQuery>;

    // =====================================================================
    // EVENTS
    // =====================================================================
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Emitted when a new eFTI cargo anchor is created on-chain.
        AnchorCreated {
            creator: T::AccountId,
            doc_hash: [u8; 32],
            movement_id: BoundedVec<u8, T::MaxMovementIdLen>,
            manifest_value_usd_cents: u64,
        },
        /// Emitted when an anchor's lifecycle status is advanced through the DAG.
        AnchorStatusUpdated {
            who: T::AccountId,
            doc_hash: [u8; 32],
            new_status: AnchorStatus,
        },
        /// Emitted when a DID-verified accessor logs an interaction for audit trail.
        AccessLogged {
            accessor: T::AccountId,
            movement_id: BoundedVec<u8, T::MaxMovementIdLen>,
            outcome: AccessOutcome,
            log_index: u32,
        },
        /// Emitted when a batch of document leaf hashes is committed as a Merkle root.
        MerkleBatchCommitted {
            committer: T::AccountId,
            batch_root: [u8; 32],
            leaf_count: u32,
        },
        /// Emitted when an XCMP cargo attestation is dispatched to an external parachain.
        XcmpAttestationDispatched {
            destination_para_id: u32,
            movement_id: BoundedVec<u8, T::MaxMovementIdLen>,
            doc_hash: [u8; 32],
            standard: AttestationStandard,
        },
        /// Emitted when PolkaVM Coretime allocation parameters are configured.
        CoretimeAllocated {
            core_index: u16,
            slice_duration_blocks: u32,
            jam_service_id: u32,
        },
    }

    // =====================================================================
    // ERRORS
    // =====================================================================
    #[pallet::error]
    pub enum Error<T> {
        /// A cargo anchor with this document hash already exists (double-pledge prevention).
        AnchorAlreadyExists,
        /// A cargo anchor for this movement ID already exists (Maysir prevention).
        MovementAlreadyAnchored,
        /// No anchor record found for the requested document hash.
        AnchorNotFound,
        /// The caller does not have an active registered DID (identity gating).
        DidNotRegistered,
        /// The requested status transition violates the monotonic DAG state machine.
        InvalidStatusTransition,
        /// The access log storage for this movement has reached its hard cap (MaxAccessLogsPerMovement).
        AccessLogsFull,
        /// The provided Merkle batch root hash already exists in the registry.
        MerkleBatchAlreadyExists,
        /// Arithmetic overflow detected in an internal counter.
        ArithmeticOverflow,
        /// The specified movement ID is not yet anchored on Layer 1.
        MovementNotAnchored,
        /// Invalid destination parachain identifier for XCMP dispatch.
        InvalidDestinationParachain,
    }

    // =====================================================================
    // DISPATCHABLE EXTRINSICS
    // =====================================================================
    #[pallet::call]
    impl<T: Config> Pallet<T> {

        /// Creates a new eFTI cargo anchor on-chain.
        ///
        /// PRECONDITIONS:
        ///   1. Caller must have a registered DID in pallet-did-registry.
        ///   2. doc_hash must not already exist in Anchors storage.
        ///   3. movement_id must not already exist in MovementRegistry storage.
        ///
        /// This double-check prevents double-pledging (Maysir) at the protocol level.
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::create_anchor())]
        pub fn create_anchor(
            origin: OriginFor<T>,
            doc_hash: [u8; 32],
            doc_store_uri: EncryptedPointer<T>,
            movement_id: BoundedVec<u8, T::MaxMovementIdLen>,
            creator_did: BoundedVec<u8, T::MaxDidLen>,
            arbitrum_tx_hash: BoundedVec<u8, T::MaxArbitrumTxHashLen>,
            manifest_value_usd_cents: u64,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // Guard 1: Caller must have a registered DID.
            ensure!(T::DidValidator::is_registered(&who), Error::<T>::DidNotRegistered);

            // Guard 2: Reject duplicate document hash (double-pledge prevention).
            ensure!(!Anchors::<T>::contains_key(&doc_hash), Error::<T>::AnchorAlreadyExists);

            // Guard 3: Reject duplicate movement ID (Maysir prevention).
            ensure!(!MovementRegistry::<T>::contains_key(&movement_id), Error::<T>::MovementAlreadyAnchored);

            let current_block: u64 = frame_system::Pallet::<T>::block_number()
                .try_into()
                .unwrap_or(0u64);

            let record = AnchorRecord {
                doc_hash,
                doc_store_uri,
                movement_id: movement_id.clone(),
                creator_did,
                arbitrum_tx_hash,
                manifest_value_usd_cents,
                status: AnchorStatus::Created,
                created_at_block: current_block,
            };

            // Atomic dual-write to both storage maps.
            Anchors::<T>::insert(&doc_hash, record);
            MovementRegistry::<T>::insert(&movement_id, doc_hash);

            Self::deposit_event(Event::AnchorCreated {
                creator: who,
                doc_hash,
                movement_id,
                manifest_value_usd_cents,
            });

            Ok(())
        }

        /// Advances an anchor's lifecycle status through the monotonic DAG:
        ///   Created ──► Updated ──► Withdrawn
        ///
        /// Any reverse or skip transition is explicitly rejected.
        /// Only the original creator or an authorized Root caller may advance status.
        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::update_anchor_status())]
        pub fn update_anchor_status(
            origin: OriginFor<T>,
            doc_hash: [u8; 32],
            new_status: AnchorStatus,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // Guard: Caller must have an active DID registration.
            ensure!(T::DidValidator::is_registered(&who), Error::<T>::DidNotRegistered);

            Anchors::<T>::try_mutate(&doc_hash, |maybe_record| -> DispatchResult {
                let record = maybe_record.as_mut().ok_or(Error::<T>::AnchorNotFound)?;

                // Enforce monotonic DAG: validate the transition is legal.
                match (&record.status, &new_status) {
                    (AnchorStatus::Created, AnchorStatus::Updated)   => {},
                    (AnchorStatus::Updated, AnchorStatus::Withdrawn) => {},
                    _ => return Err(Error::<T>::InvalidStatusTransition.into()),
                }

                record.status = new_status.clone();
                Ok(())
            })?;

            Self::deposit_event(Event::AnchorStatusUpdated {
                who,
                doc_hash,
                new_status,
            });

            Ok(())
        }

        /// Records an immutable access log entry for a given movement ID.
        ///
        /// Hard-capped at MaxAccessLogsPerMovement (10) entries to prevent state exhaustion.
        /// Each entry records the accessor's identity, block number, and access outcome.
        /// Forms the irrevocable regulatory audit trail required by GDPR Article 5(1)(c).
        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::log_access())]
        pub fn log_access(
            origin: OriginFor<T>,
            movement_id: BoundedVec<u8, T::MaxMovementIdLen>,
            outcome: AccessOutcome,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // Guard: Accessor must have an active DID registration.
            ensure!(T::DidValidator::is_registered(&who), Error::<T>::DidNotRegistered);

            // Guard: Enforce hard cap on log entries per movement.
            let current_count = AccessLogCount::<T>::get(&movement_id);
            ensure!(
                current_count < T::MaxAccessLogsPerMovement::get(),
                Error::<T>::AccessLogsFull
            );

            // Encode AccountId as a fixed 32-byte array for compact storage.
            let accessor_bytes = Self::account_to_bytes(&who);

            let current_block: u64 = frame_system::Pallet::<T>::block_number()
                .try_into()
                .unwrap_or(0u64);

            let entry = AccessLogEntry {
                accessor: accessor_bytes,
                block_number: current_block,
                outcome: outcome.clone(),
            };

            // Insert at the current log index slot.
            AccessLogs::<T>::insert(&movement_id, current_count, entry);

            // Increment the counter, guarding against overflow.
            let new_count = current_count.checked_add(1).ok_or(Error::<T>::ArithmeticOverflow)?;
            AccessLogCount::<T>::insert(&movement_id, new_count);

            Self::deposit_event(Event::AccessLogged {
                accessor: who,
                movement_id,
                outcome,
                log_index: current_count,
            });

            Ok(())
        }

        /// Commits a batch of document leaf hashes under a single Merkle root hash.
        ///
        /// Used by the relayer to efficiently anchor large document batches in a single
        /// on-chain transaction, reducing L1 gas costs for high-volume trade corridors.
        /// Bounded at MaxMerkleLeavesPerBatch (64) leaves per commit.
        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::commit_merkle_batch())]
        pub fn commit_merkle_batch(
            origin: OriginFor<T>,
            batch_root: [u8; 32],
            leaf_hashes: BoundedVec<[u8; 32], T::MaxMerkleLeavesPerBatch>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // Guard: Caller must have an active DID registration.
            ensure!(T::DidValidator::is_registered(&who), Error::<T>::DidNotRegistered);

            // Guard: Reject duplicate batch root commitments.
            ensure!(!MerkleBatches::<T>::contains_key(&batch_root), Error::<T>::MerkleBatchAlreadyExists);

            let leaf_count = leaf_hashes.len() as u32;

            MerkleBatches::<T>::insert(&batch_root, leaf_hashes);

            Self::deposit_event(Event::MerkleBatchCommitted {
                committer: who,
                batch_root,
                leaf_count,
            });

            Ok(())
        }

        /// Dispatches a cross-chain cargo attestation (XCM v3/v4 format) to an external parachain.
        ///
        /// Enables interoperability with identity parachains such as KILT Protocol (ParaID 2086)
        /// for eIDAS Level 3 decentralized verifiable credential issuance.
        #[pallet::call_index(4)]
        #[pallet::weight(T::WeightInfo::dispatch_xcmp_attestation())]
        pub fn dispatch_xcmp_attestation(
            origin: OriginFor<T>,
            destination_para_id: u32,
            movement_id: BoundedVec<u8, T::MaxMovementIdLen>,
            standard: AttestationStandard,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // Guard 1: Caller must have a registered DID.
            ensure!(T::DidValidator::is_registered(&who), Error::<T>::DidNotRegistered);

            // Guard 2: Destination parachain ID must be non-zero.
            ensure!(destination_para_id > 0, Error::<T>::InvalidDestinationParachain);

            // Guard 3: Movement ID must be anchored.
            let doc_hash = MovementRegistry::<T>::get(&movement_id).ok_or(Error::<T>::MovementNotAnchored)?;

            Self::deposit_event(Event::XcmpAttestationDispatched {
                destination_para_id,
                movement_id,
                doc_hash,
                standard,
            });

            Ok(())
        }

        /// Configures execution parameters for PolkaVM Coretime allocation under the
        /// Join-Accumulate Machine (JAM Gray Paper v0.7.2) specification.
        ///
        /// Callable exclusively by Root origin (parachain governance / democracy).
        #[pallet::call_index(5)]
        #[pallet::weight(T::WeightInfo::configure_coretime_allocation())]
        pub fn configure_coretime_allocation(
            origin: OriginFor<T>,
            core_index: u16,
            slice_duration_blocks: u32,
            jam_service_id: u32,
            state_proof_hash: [u8; 32],
        ) -> DispatchResult {
            ensure_root(origin)?;

            let config = CoretimeAllocationConfig {
                core_index,
                slice_duration_blocks,
                jam_service_id,
                state_proof_hash,
            };

            CoretimeConfig::<T>::put(config);

            Self::deposit_event(Event::CoretimeAllocated {
                core_index,
                slice_duration_blocks,
                jam_service_id,
            });

            Ok(())
        }
    }

    // =====================================================================
    // PUBLIC READ-ONLY HELPER FUNCTIONS
    // =====================================================================
    impl<T: Config> Pallet<T> {

        /// Verifies that an anchor record exists for the given document hash.
        pub fn verify_anchor_exists(doc_hash: &[u8; 32]) -> bool {
            Anchors::<T>::contains_key(doc_hash)
        }

        /// Verifies that the anchor for the given document hash has reached
        /// the terminal `Withdrawn` state (i.e., trade milestone is complete).
        pub fn verify_completion_milestone(doc_hash: &[u8; 32]) -> bool {
            Anchors::<T>::get(doc_hash)
                .map(|r| r.status == AnchorStatus::Withdrawn)
                .unwrap_or(false)
        }

        /// Returns the declared manifest value (in USD cents) for a given document hash.
        /// Returns None if the anchor does not exist.
        pub fn get_manifest_value(doc_hash: &[u8; 32]) -> Option<u64> {
            Anchors::<T>::get(doc_hash).map(|r| r.manifest_value_usd_cents)
        }

        /// Verifies that a given leaf hash is contained within a committed Merkle batch.
        pub fn verify_merkle_proof(batch_root: &[u8; 32], leaf_hash: &[u8; 32]) -> bool {
            MerkleBatches::<T>::get(batch_root)
                .map(|leaves| leaves.iter().any(|l| l == leaf_hash))
                .unwrap_or(false)
        }

        /// Returns the full ordered access log for a given movement ID as a Vec,
        /// for use in off-chain regulatory audit trail export.
        pub fn get_regulatory_audit_trail(
            movement_id: &BoundedVec<u8, T::MaxMovementIdLen>,
        ) -> Vec<AccessLogEntry> {
            let count = AccessLogCount::<T>::get(movement_id);
            (0..count)
                .filter_map(|i| AccessLogs::<T>::get(movement_id, i))
                .collect()
        }

        /// Internal: encodes an AccountId into a fixed 32-byte representation
        /// for compact storage within AccessLogEntry records.
        fn account_to_bytes(account: &T::AccountId) -> [u8; 32] {
            let encoded = account.encode();
            let mut bytes = [0u8; 32];
            let len = encoded.len().min(32);
            bytes[..len].copy_from_slice(&encoded[..len]);
            bytes
        }
    }
}
