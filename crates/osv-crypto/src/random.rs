use std::{error::Error, fmt};

/// Failure to fill an entire cryptographic-randomness request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RandomError;

impl fmt::Display for RandomError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("cryptographic randomness unavailable")
    }
}

impl Error for RandomError {}

/// Exact-fill CSPRNG interface, injectable for deterministic vectors and failures.
pub trait RandomSource {
    /// Fills all of `destination` or returns an error.
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), RandomError>;
}

/// Operating-system cryptographic random source.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemRandom;

impl RandomSource for SystemRandom {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), RandomError> {
        getrandom::fill(destination).map_err(|_| RandomError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_rng_fills_request() {
        let mut output = [0_u8; 32];
        SystemRandom.fill(&mut output).unwrap();
        assert_ne!(output, [0; 32]);
    }
}
