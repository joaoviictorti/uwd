/// Randomly shuffles the elements of a mutable slice in-place using a pseudo-random
/// number generator seeded by the CPU's timestamp counter (`rdtsc`).
///
/// The shuffling algorithm is a variant of the Fisher-Yates shuffle.
///
/// # Arguments
/// 
/// * `list` — A mutable slice of elements to be shuffled.
pub fn shuffle<T>(list: &mut [T]) {
    let mut seed = rdtsc();
    for i in (1..list.len()).rev() {
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        let j = seed as usize % (i + 1);
        list.swap(i, j);
    }
}

/// Reads the CPU's time-stamp counter using the `rdtsc` instruction, which returns the
/// number of cycles since the last reset.
///
/// This can be used as a fast, low-quality entropy source for seeding simple randomization routines.
///
/// # Returns
/// 
/// * The 64-bit timestamp value combining the contents of EDX:EAX registers.
#[inline(always)]
fn rdtsc() -> u64 {
    unsafe {
        let mut low: u32;
        let mut high: u32;
        core::arch::asm!("rdtsc", out("eax") low, out("edx") high);
        ((high as u64) << 32) | (low as u64)
    }
}