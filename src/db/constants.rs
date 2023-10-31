use std::num::NonZeroU32;

pub const SIG_COLLECTION: &str = "signatures";
pub const SIG_ID_COLLECTION: &str = "sig_ids";
pub const SIG_TTL: u32 = 3600;
pub const SECRET_COLLECTION: &str = "secrets";

pub const PBKDF2_ITERATIONS: Option<NonZeroU32> = NonZeroU32::new(100_000);
pub const SALT_BASE: [u8; 16] = [
    // This value was generated from a secure PRNG.
    0xd6, 0x26, 0x98, 0xda, 0xf4, 0xdc, 0x50, 0x52, 0x24, 0xf2, 0x27, 0xd1, 0xfe, 0x39, 0x01, 0x8a,
];
