use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Auth,
    Malformed,
    Truncated,
    Replay,
    Policy,
    Key,
    Range,
}

impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Error::Auth => "AUTH_FAILED",
            Error::Malformed => "MALFORMED",
            Error::Truncated => "TRUNCATED",
            Error::Replay => "REPLAY",
            Error::Policy => "POLICY",
            Error::Key => "KEY",
            Error::Range => "RANGE",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code())
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
