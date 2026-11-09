use crate::error::{Error, Result};

/// Padded length for `length` bytes given the maximum message size.
/// Implements Algorithm 1 from the PURB paper (PETS 2019).
pub fn padme(length: usize, max_length: usize) -> Result<usize> {
    if max_length < length.max(1) {
        return Err(Error::Range);
    }
    if length == 0 {
        return Ok(0);
    }
    if length == 1 {
        return Ok(1);
    }
    let e = (length as f64).log2().floor() as u32;
    let s = (e as f64).log2().floor() as u32 + 1;
    if e <= s {
        return Ok(length);
    }
    let z = e - s;
    let step = 1usize << z;
    let mask = step - 1;
    Ok((length + mask) / step * step)
}

/// Number of bits leaked by the padded length (enumerated for M <= 2^20).
pub fn padme_leakage_bits(max_length: usize) -> Result<u32> {
    if max_length > 1 << 20 {
        return Err(Error::Range);
    }
    if max_length <= 1 {
        return Ok(0);
    }
    let mut seen = std::collections::BTreeSet::new();
    for len in 1..=max_length {
        seen.insert(padme(len, max_length)?);
    }
    Ok((seen.len() as f64).log2().ceil() as u32)
}
