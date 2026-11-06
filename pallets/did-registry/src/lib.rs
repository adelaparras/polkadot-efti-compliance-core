// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Alejandro De La Parra Solomon. All rights reserved.
// Custodianship and Data Controller: Solomon Brokerage OÜ (Tallinn, Republic of Estonia)
//
// Appendix XIII.B: pallet-did-registry: Hardened Identity Specification
// Final Compile-Hardened Production Version 1.0 (WASM & PVM Compatible)

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

// =====================================================================
// TRAIT DEFINITIONS (CRATE LEVEL)
// =====================================================================
/// Decoupled identity validation trait to allow loose coupling between custom pallets.
/// This allows neighboring pallets to query the identity registry at runtime without
/// introducing hard compile-time dependencies.
pub trait DidValidator<AccountId, Did> {
    /// Read-only check: verifies that the caller's AccountId is bound to the declared DID.
    fn is_valid_did(account: &AccountId, did: &Did) -> bool;
}

#[frame_support::pallet]
pub mod pallet {
    use frame_support::{
        dispatch::DispatchResult,
        pallet_prelude::*,
    };
    use frame_system::pallet_prelude::*;
    use sp_std::vec::Vec;

    // =====================================================================
    // CONFIG TRAIT DEFINITION
    // =====================================================================
    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The overarching event type.
        /// Essential for allowing the macro-expanded deposit_event call to compile.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Hard-coded static constraint for DID length to prevent state bloat.
        /// Prevents memory-exhaustion or state-inflation Denial of Service (DoS) attacks.
        #[pallet::constant]
        type MaxDidLength: Get<u32>;
    }

    const STORAGE_VERSION: StorageVersion = StorageVersion::new(2);

    #[pallet::pallet]
    #[pallet::storage_version(STORAGE_VERSION)]
    pub struct Pallet<T>(_);

    // =====================================================================
    // STORAGE MAPS
    // =====================================================================
    /// Primary Identity Map: maps an AccountId to a bounded W3C DID string.
    /// Hashing Strategy: Blake2_128Concat provides cryptographic preimage resistance
    /// and enables safe key-value query traversals.
    #[pallet::storage]
    #[pallet::getter(fn did_of)]
    pub type DidOf<T: Config> = StorageMap<
        _,
        Blake2_128Concat, T::AccountId,
        BoundedVec<u8, T::MaxDidLength>,
        OptionQuery,
    >;

    /// Reverse lookup registry: maps a bounded DID string back to its AccountId.
    /// Enforces the strict 1:1 bi-directional identity uniqueness constraint on-chain.
    #[pallet::storage]
    #[pallet::getter(fn account_of_did)]
    pub type AccountOfDid<T: Config> = StorageMap<
        _,
        Blake2_128Concat, BoundedVec<u8, T::MaxDidLength>,
        T::AccountId,
        OptionQuery,
    >;

    // =====================================================================
    // PALLET EVENTS
    // =====================================================================
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Emitted when a new AccountId is bound to a verified DID string.
        DidRegistered {
            account: T::AccountId,
            did: BoundedVec<u8, T::MaxDidLength>,
        },
        /// Emitted when an existing DID binding is rotated.
        DidUpdated {
            account: T::AccountId,
            old_did: BoundedVec<u8, T::MaxDidLength>,
            new_did: BoundedVec<u8, T::MaxDidLength>,
        },
        /// Emitted when an identity binding is removed.
        DidUnregistered {
            account: T::AccountId,
            did: BoundedVec<u8, T::MaxDidLength>,
        },
    }

    // =====================================================================
    // PALLET ERRORS
    // =====================================================================
    #[pallet::error]
    pub enum Error<T> {
        /// The provided DID string length exceeds the MaxDidLength constraint.
        DidTooLong,
        /// The DID string is already registered to another active account.
        DidAlreadyBound,
        /// The caller account is already bound to a registered DID.
        AccountAlreadyBound,
        /// No active identity record found for the requesting account.
        DidNotFound,
    }

    // =====================================================================
    // DISPATCHABLE EXTRINSICS (CALLS)
    // =====================================================================
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Binds the signing AccountId to a unique, W3C-compliant DID string.
        /// Prevents Sybil attacks by enforcing a strict 1:1 bi-directional mapping.
        #[pallet::call_index(0)]
        #[pallet::weight(10_000)] // Static weight replaced by dynamic benchmark in spec (using fixed for now as weight module not generated)
        pub fn register_did(
            origin: OriginFor<T>,
            did: Vec<u8>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let max_len = T::MaxDidLength::get() as usize;

            // Step 1: Enforce storage bounding limits
            ensure!(did.len() <= max_len, Error::<T>::DidTooLong);
            let did_bounded: BoundedVec<u8, T::MaxDidLength> = did.try_into().map_err(|_| Error::<T>::DidTooLong)?;

            // Step 2: Enforce bi-directional 1:1 uniqueness mappings
            ensure!(!DidOf::<T>::contains_key(&who), Error::<T>::AccountAlreadyBound);
            ensure!(!AccountOfDid::<T>::contains_key(&did_bounded), Error::<T>::DidAlreadyBound);

            // Step 3: Write atomically to both maps
            DidOf::<T>::insert(&who, &did_bounded);
            AccountOfDid::<T>::insert(&did_bounded, &who);

            Self::deposit_event(Event::DidRegistered {
                account: who,
                did: did_bounded,
            });

            Ok(())
        }

        /// Updates or rotates an existing identity record.
        /// Enforces registration existence and target uniqueness prior to rotation.
        #[pallet::call_index(1)]
        #[pallet::weight(10_000)]
        pub fn update_did(
            origin: OriginFor<T>,
            new_did: Vec<u8>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let max_len = T::MaxDidLength::get() as usize;

            // Step 1: Verify current registration exists
            let old_did = DidOf::<T>::get(&who).ok_or(Error::<T>::DidNotFound)?;

            // Step 2: Enforce storage bounds for the rotated value
            ensure!(new_did.len() <= max_len, Error::<T>::DidTooLong);
            let new_did_bounded: BoundedVec<u8, T::MaxDidLength> = new_did.try_into().map_err(|_| Error::<T>::DidTooLong)?;

            // Step 3: Verify the rotated identity is not claimed by another active account
            ensure!(!AccountOfDid::<T>::contains_key(&new_did_bounded), Error::<T>::DidAlreadyBound);

            // Step 4: Atomic mutation
            AccountOfDid::<T>::remove(&old_did);
            DidOf::<T>::insert(&who, &new_did_bounded);
            AccountOfDid::<T>::insert(&new_did_bounded, &who);

            Self::deposit_event(Event::DidUpdated {
                account: who,
                old_did,
                new_did: new_did_bounded,
            });

            Ok(())
        }

        /// Unregisters an active identity record, removing the AccountId-DID binding.
        /// Fully cleanses both storage maps to prevent partial record leaks.
        #[pallet::call_index(2)]
        #[pallet::weight(10_000)]
        pub fn unregister_did(
            origin: OriginFor<T>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // Remove the AccountId mapping; revert if not registered
            let did = DidOf::<T>::take(&who).ok_or(Error::<T>::DidNotFound)?;
            AccountOfDid::<T>::remove(&did);

            Self::deposit_event(Event::DidUnregistered {
                account: who,
                did,
            });

            Ok(())
        }
    }

    // =====================================================================
    // PUBLIC VIEW AND IDENTITY HELPERS
    // =====================================================================
    impl<T: Config> Pallet<T> {
        /// Read-only utility: returns the bound DID string for an account.
        pub fn get_did(account: &T::AccountId) -> Option<Vec<u8>> {
            DidOf::<T>::get(account).map(|b| b.to_vec())
        }

        /// Read-only utility: returns the associated AccountId for a DID.
        pub fn lookup_account(did: &[u8]) -> Option<T::AccountId> {
            let key: BoundedVec<u8, T::MaxDidLength> = did.to_vec().try_into().ok()?;
            AccountOfDid::<T>::get(key)
        }
    }

    // =====================================================================
    // DECOUPLED INTEGRATION TRAIT IMPLEMENTATION
    // =====================================================================
    impl<T: Config> super::DidValidator<T::AccountId, BoundedVec<u8, T::MaxDidLength>> for Pallet<T> {
        /// Performs the decoupled validation check required by neighboring pallets.
        fn is_valid_did(account: &T::AccountId, did: &BoundedVec<u8, T::MaxDidLength>) -> bool {
            if let Some(registered_did) = DidOf::<T>::get(account) {
                registered_did == *did
            } else {
                false
            }
        }
    }
}
