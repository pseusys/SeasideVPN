use rand::CryptoRng;
use rand::Rng;

#[cfg(test)]
struct MockRng;

#[cfg(test)]
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

#[cfg(test)]
impl CryptoRng for MockRng {}

#[inline]
#[cfg(test)]
pub(crate) fn get_rng() -> impl Rng + CryptoRng {
    MockRng
}

#[inline]
#[cfg(not(test))]
pub(crate) fn get_rng() -> impl Rng + CryptoRng {
    rand::rngs::OsRng
}
