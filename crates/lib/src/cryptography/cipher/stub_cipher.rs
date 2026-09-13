use generic_array::typenum::U32;

use crate::*;

#[allow(dead_code, reason = "marker used in tests")]
#[derive(Debug, PartialEq)]
pub struct StubCipher;

impl Cipher for StubCipher {
    const NAME: &'static str = "STUB";

    type NonceSize = U32;
    type AuthorizationTagSize = U32;
    type Error = Box<&'static (dyn std::error::Error + Send + Sync)>;

    fn encrypt(
        _nonce: &Nonce<Self::NonceSize>,
        _data_key: &DataKey,
        _in_place_buffer: &mut [u8],
        _associated_data: &[u8],
    ) -> Result<AuthorizationTag<Self>, Self::Error> {
        unimplemented!()
    }

    fn decrypt(
        _nonce: &Nonce<Self::NonceSize>,
        _data_key: &DataKey,
        _in_place_buffer: &mut [u8],
        _associated_data: &[u8],
        _authorization_tag: &AuthorizationTag<Self>,
    ) -> Result<(), Self::Error> {
        unimplemented!()
    }
}
