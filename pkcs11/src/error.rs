//! An error from PKCS #11.

use std::{error, fmt, result};
use pkcs11_sys as sys;


#[derive(Clone, Debug)]
pub struct Error {
    raw: sys::CK_RV,
}

impl Error {
    pub fn error_code(&self) -> sys::CK_RV {
        self.raw
    }
}

impl From<sys::CK_RV> for Error {
    fn from(err: sys::CK_RV) -> Self {
        Error{raw: err}
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match self.raw {
            // XXX Add lots and lots of cases here.
            _ => "unknown error"
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        error::Error::description(self).fmt(f)
    }
}


pub type Result<T> = result::Result<T, Error>;
