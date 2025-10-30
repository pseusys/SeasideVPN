use rand::CryptoRng;
use rand::Rng;

#[cfg(any(feature = "test", test))]
struct MockRng;

#[cfg(any(feature = "test", test))]
impl rand::RngCore for MockRng {
    fn next_u32(&mut self) -> u32 {
        0u32
    }

    fn next_u64(&mut self) -> u64 {
        0u64
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(0u8)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        Ok(dest.fill(0u8))
    }
}

#[cfg(any(feature = "test", test))]
impl CryptoRng for MockRng {}

#[inline]
#[cfg(any(feature = "test", test))]
pub(crate) fn get_rng() -> impl Rng + CryptoRng {
    MockRng
}

#[inline]
#[cfg(not(any(feature = "test", test)))]
pub(crate) fn get_rng() -> impl Rng + CryptoRng {
    rand::rngs::OsRng
}
