use crate as pallet_efti_anchor_vc;
use frame_support::{
	parameter_types,
	traits::{ConstU16, ConstU64},
};
use sp_core::H256;
use sp_runtime::{
	testing::Header,
	traits::{BlakeTwo256, IdentityLookup},
};

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
	pub enum Test where
		Block = Block,
		NodeBlock = Block,
		UncheckedExtrinsic = UncheckedExtrinsic,
	{
		System: frame_system,
        DidRegistry: pallet_did_registry,
		EftiAnchorVc: pallet_efti_anchor_vc,
	}
);

impl frame_system::Config for Test {
	type BaseCallFilter = frame_support::traits::Everything;
	type BlockWeights = ();
	type BlockLength = ();
	type DbWeight = ();
	type RuntimeOrigin = RuntimeOrigin;
	type RuntimeCall = RuntimeCall;
	type Nonce = u64;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = u64;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Block = Block;
	type RuntimeEvent = RuntimeEvent;
	type BlockHashCount = ConstU64<250>;
	type Version = ();
	type PalletInfo = PalletInfo;
	type AccountData = ();
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = ();
	type SS58Prefix = ConstU16<42>;
	type OnSetCode = ();
	type MaxConsumers = frame_support::traits::ConstU32<16>;
}

parameter_types! {
	pub const MaxDidLength: u32 = 128;
}

impl pallet_did_registry::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type MaxDidLength = MaxDidLength;
    type WeightInfo = ();
}

parameter_types! {
	pub const MaxUriLen: u32 = 256;
    pub const MaxMovementIdLen: u32 = 64;
    pub const MaxDidLen: u32 = 128;
    pub const MaxEncryptedKeyPtrLen: u32 = 256;
    pub const MaxArbitrumTxHashLen: u32 = 128;
    pub const MaxAccessLogsPerMovement: u32 = 10;
    pub const MaxMerkleLeavesPerBatch: u32 = 64;
}

// Implement the DidValidator trait for the Test runtime
pub struct MockDidValidator;
impl pallet_efti_anchor_vc::DidValidator<u64> for MockDidValidator {
    fn is_registered(who: &u64) -> bool {
        pallet_did_registry::Pallet::<Test>::is_registered(who)
    }
}

impl pallet_efti_anchor_vc::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type MaxUriLen = MaxUriLen;
    type MaxMovementIdLen = MaxMovementIdLen;
    type MaxDidLen = MaxDidLen;
    type MaxEncryptedKeyPtrLen = MaxEncryptedKeyPtrLen;
    type MaxArbitrumTxHashLen = MaxArbitrumTxHashLen;
    type MaxAccessLogsPerMovement = MaxAccessLogsPerMovement;
    type MaxMerkleLeavesPerBatch = MaxMerkleLeavesPerBatch;
    type DidValidator = MockDidValidator;
    type WeightInfo = ();
}

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
	frame_system::GenesisConfig::default().build_storage::<Test>().unwrap().into()
}
