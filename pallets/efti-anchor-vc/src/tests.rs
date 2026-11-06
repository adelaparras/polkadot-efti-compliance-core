use crate::{mock::*, *};
use frame_support::{assert_noop, assert_ok, BoundedVec};

#[test]
fn create_anchor_works() {
	new_test_ext().execute_with(|| {
        // 1. Register DID for account 1
        let did_bytes = b"did:polkadot:5GrwvaEFzXb26Hv7FvijU5it5mcd965920a08".to_vec();
        let did: BoundedVec<u8, MaxDidLength> = BoundedVec::try_from(did_bytes).unwrap();
        assert_ok!(DidRegistry::register_did(RuntimeOrigin::signed(1), did));

        // 2. Create Anchor
        let doc_hash = [1u8; 32];
        let uri_bytes = b"ipfs://QmCargoManifest001".to_vec();
        let uri: BoundedVec<u8, MaxUriLen> = BoundedVec::try_from(uri_bytes).unwrap();
        let meta_bytes = b"kms:wrapped:key_id_123".to_vec();
        let meta: BoundedVec<u8, MaxEncryptedKeyPtrLen> = BoundedVec::try_from(meta_bytes).unwrap();
        
        let doc_store_uri = EncryptedPointer {
            cid_or_url: uri,
            storage_type: 1,
            encryption_scheme: 1,
            encryption_meta: meta,
        };

        let movement_bytes = b"MOVE-2026-NORDIC-001".to_vec();
        let movement_id: BoundedVec<u8, MaxMovementIdLen> = BoundedVec::try_from(movement_bytes).unwrap();
        let creator_did: BoundedVec<u8, MaxDidLen> = BoundedVec::try_from(b"did:polkadot:5GrwvaEFzXb26Hv7FvijU5it5mcd965920a08".to_vec()).unwrap();
        let arbitrum_tx: BoundedVec<u8, MaxArbitrumTxHashLen> = BoundedVec::try_from(b"0xabcdef1234567890".to_vec()).unwrap();

		assert_ok!(EftiAnchorVc::create_anchor(
            RuntimeOrigin::signed(1), 
            doc_hash, 
            doc_store_uri, 
            movement_id.clone(),
            creator_did,
            arbitrum_tx,
            50_000_000 // $500,000.00 USD
        ));

        // Check storage
        assert!(EftiAnchorVc::verify_anchor_exists(&doc_hash));
        assert_eq!(EftiAnchorVc::get_manifest_value(&doc_hash), Some(50_000_000));
	});
}

#[test]
fn create_anchor_fails_if_no_did() {
	new_test_ext().execute_with(|| {
        let doc_hash = [2u8; 32];
        let uri: BoundedVec<u8, MaxUriLen> = BoundedVec::try_from(b"ipfs://QmHash".to_vec()).unwrap();
        let meta: BoundedVec<u8, MaxEncryptedKeyPtrLen> = BoundedVec::try_from(b"meta".to_vec()).unwrap();
        let doc_store_uri = EncryptedPointer {
            cid_or_url: uri,
            storage_type: 1,
            encryption_scheme: 1,
            encryption_meta: meta,
        };
        let movement_id: BoundedVec<u8, MaxMovementIdLen> = BoundedVec::try_from(b"move_2".to_vec()).unwrap();
        let creator_did: BoundedVec<u8, MaxDidLen> = BoundedVec::try_from(b"did:unregistered".to_vec()).unwrap();
        let arbitrum_tx: BoundedVec<u8, MaxArbitrumTxHashLen> = BoundedVec::try_from(b"0x0".to_vec()).unwrap();

		assert_noop!(
            EftiAnchorVc::create_anchor(
                RuntimeOrigin::signed(2), 
                doc_hash, 
                doc_store_uri, 
                movement_id,
                creator_did,
                arbitrum_tx,
                1000
            ),
            Error::<Test>::DidNotRegistered
        );
	});
}

#[test]
fn log_access_works() {
    new_test_ext().execute_with(|| {
        let did: BoundedVec<u8, MaxDidLength> = BoundedVec::try_from(b"did:polkadot:accessor".to_vec()).unwrap();
        assert_ok!(DidRegistry::register_did(RuntimeOrigin::signed(1), did));

        let movement_id: BoundedVec<u8, MaxMovementIdLen> = BoundedVec::try_from(b"move_1".to_vec()).unwrap();

        assert_ok!(EftiAnchorVc::log_access(
            RuntimeOrigin::signed(1),
            movement_id.clone(),
            AccessOutcome::Granted
        ));

        assert_eq!(EftiAnchorVc::access_log_count(&movement_id), 1);
    });
}

#[test]
fn dispatch_xcmp_attestation_works() {
    new_test_ext().execute_with(|| {
        let did: BoundedVec<u8, MaxDidLength> = BoundedVec::try_from(b"did:polkadot:exporter".to_vec()).unwrap();
        assert_ok!(DidRegistry::register_did(RuntimeOrigin::signed(1), did));

        let doc_hash = [42u8; 32];
        let uri: BoundedVec<u8, MaxUriLen> = BoundedVec::try_from(b"ipfs://QmXcmpCargo".to_vec()).unwrap();
        let meta: BoundedVec<u8, MaxEncryptedKeyPtrLen> = BoundedVec::try_from(b"kms:key".to_vec()).unwrap();
        let doc_store_uri = EncryptedPointer {
            cid_or_url: uri,
            storage_type: 1,
            encryption_scheme: 1,
            encryption_meta: meta,
        };
        let movement_id: BoundedVec<u8, MaxMovementIdLen> = BoundedVec::try_from(b"MOVE-XCMP-001".to_vec()).unwrap();
        let creator_did: BoundedVec<u8, MaxDidLen> = BoundedVec::try_from(b"did:polkadot:exporter".to_vec()).unwrap();
        let arbitrum_tx: BoundedVec<u8, MaxArbitrumTxHashLen> = BoundedVec::try_from(b"0xarb123".to_vec()).unwrap();

        assert_ok!(EftiAnchorVc::create_anchor(
            RuntimeOrigin::signed(1), 
            doc_hash, 
            doc_store_uri, 
            movement_id.clone(),
            creator_did,
            arbitrum_tx,
            75_000_000
        ));

        // Dispatch to KILT Protocol parachain (ParaID 2086) for eIDAS Level 3 credential issuance
        assert_ok!(EftiAnchorVc::dispatch_xcmp_attestation(
            RuntimeOrigin::signed(1),
            2086,
            movement_id.clone(),
            AttestationStandard::W3cVerifiableCredential
        ));

        System::assert_last_event(Event::XcmpAttestationDispatched {
            destination_para_id: 2086,
            movement_id,
            doc_hash,
            standard: AttestationStandard::W3cVerifiableCredential,
        }.into());
    });
}

#[test]
fn configure_coretime_allocation_works() {
    new_test_ext().execute_with(|| {
        // Root caller configures Coretime allocation under JAM Gray Paper v0.7.2 specification
        let proof_hash = [7u8; 32];
        assert_ok!(EftiAnchorVc::configure_coretime_allocation(
            RuntimeOrigin::root(),
            1,   // Core index 1
            100, // 100 block slices
            42,  // JAM Service ID 42
            proof_hash
        ));

        let config = EftiAnchorVc::coretime_config().expect("Coretime config should be set");
        assert_eq!(config.core_index, 1);
        assert_eq!(config.slice_duration_blocks, 100);
        assert_eq!(config.jam_service_id, 42);
        assert_eq!(config.state_proof_hash, proof_hash);
    });
}
