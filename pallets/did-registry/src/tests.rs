use crate::{mock::*, Error, Event};
use frame_support::{assert_noop, assert_ok, BoundedVec};

#[test]
fn register_did_works() {
	new_test_ext().execute_with(|| {
        let did_bytes = b"did:example:123".to_vec();
        let did: BoundedVec<u8, MaxDidLength> = BoundedVec::try_from(did_bytes.clone()).unwrap();

		// Dispatch a signed extrinsic.
		assert_ok!(DidRegistry::register_did(RuntimeOrigin::signed(1), did.clone()));
		
        // Read pallet storage and assert an expected result.
		assert!(DidRegistry::is_registered(&1));
        assert_eq!(DidRegistry::dids(1), Some(did.clone()));

        // Check event
        System::assert_last_event(Event::DidRegistered { who: 1, did }.into());
	});
}
