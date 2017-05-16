//! Error handling.

use std::{error, fmt, io};
use pkcs11_sys as sys;


//------------ Error -------------------------------------------------------

/// A raw error from the underlying PKCS#11 library.
#[derive(Copy, Clone, Eq, Hash, PartialEq)]
pub struct Error(sys::CK_RV);

impl Error {
    pub fn error_code(&self) -> sys::CK_RV {
        self.0
    }
}


// Constants
pub const R_OK: Error = Error(sys::CKR_OK);
pub const R_CANCEL: Error = Error(sys::CKR_CANCEL);
pub const R_HOST_MEMORY: Error = Error(sys::CKR_HOST_MEMORY);
pub const R_SLOT_ID_INVALID: Error = Error(sys::CKR_SLOT_ID_INVALID);
pub const R_GENERAL_ERROR: Error = Error(sys::CKR_GENERAL_ERROR);
pub const R_FUNCTION_FAILED: Error = Error(sys::CKR_FUNCTION_FAILED);
pub const R_ARGUMENTS_BAD: Error = Error(sys::CKR_ARGUMENTS_BAD);
pub const R_NO_EVENT: Error = Error(sys::CKR_NO_EVENT);
pub const R_NEED_TO_CREATE_THREADS: Error
    = Error(sys::CKR_NEED_TO_CREATE_THREADS);
pub const R_CANT_LOCK: Error = Error(sys::CKR_CANT_LOCK);
pub const R_ATTRIBUTE_READ_ONLY : Error
    = Error(sys::CKR_ATTRIBUTE_READ_ONLY);
pub const R_ATTRIBUTE_SENSITIVE : Error
    = Error(sys::CKR_ATTRIBUTE_SENSITIVE);
pub const R_ATTRIBUTE_TYPE_INVALID : Error
    = Error(sys::CKR_ATTRIBUTE_TYPE_INVALID);
pub const R_ATTRIBUTE_VALUE_INVALID : Error
    = Error(sys::CKR_ATTRIBUTE_VALUE_INVALID);
pub const R_ACTION_PROHIBITED: Error = Error(sys::CKR_ACTION_PROHIBITED);
pub const R_DATA_INVALID: Error = Error(sys::CKR_DATA_INVALID);
pub const R_DATA_LEN_RANGE: Error = Error(sys::CKR_DATA_LEN_RANGE);
pub const R_DEVICE_ERROR: Error = Error(sys::CKR_DEVICE_ERROR);
pub const R_DEVICE_MEMORY: Error = Error(sys::CKR_DEVICE_MEMORY);
pub const R_DEVICE_REMOVED: Error = Error(sys::CKR_DEVICE_REMOVED);
pub const R_ENCRYPTED_DATA_INVALID : Error
    = Error(sys::CKR_ENCRYPTED_DATA_INVALID);
pub const R_ENCRYPTED_DATA_LEN_RANGE: Error
    = Error(sys::CKR_ENCRYPTED_DATA_LEN_RANGE);
pub const R_FUNCTION_CANCELED: Error = Error(sys::CKR_FUNCTION_CANCELED);
pub const R_FUNCTION_NOT_PARALLEL: Error
    = Error(sys::CKR_FUNCTION_NOT_PARALLEL);
pub const R_FUNCTION_NOT_SUPPORTED: Error
    = Error(sys::CKR_FUNCTION_NOT_SUPPORTED);
pub const R_KEY_HANDLE_INVALID: Error = Error(sys::CKR_KEY_HANDLE_INVALID);
pub const R_KEY_SIZE_RANGE: Error = Error(sys::CKR_KEY_SIZE_RANGE);
pub const R_KEY_TYPE_INCONSISTENT: Error
    = Error(sys::CKR_KEY_TYPE_INCONSISTENT);
pub const R_KEY_NOT_NEEDED: Error = Error(sys::CKR_KEY_NOT_NEEDED);
pub const R_KEY_CHANGED: Error = Error(sys::CKR_KEY_CHANGED);
pub const R_KEY_NEEDED: Error = Error(sys::CKR_KEY_NEEDED);
pub const R_KEY_INDIGESTIBLE: Error = Error(sys::CKR_KEY_INDIGESTIBLE);
pub const R_KEY_FUNCTION_NOT_PERMITTED: Error
    = Error(sys::CKR_KEY_FUNCTION_NOT_PERMITTED);
pub const R_KEY_NOT_WRAPPABLE: Error = Error(sys::CKR_KEY_NOT_WRAPPABLE);
pub const R_KEY_UNEXTRACTABLE: Error = Error(sys::CKR_KEY_UNEXTRACTABLE);
pub const R_MECHANISM_INVALID: Error = Error(sys::CKR_MECHANISM_INVALID);
pub const R_MECHANISM_PARAM_INVALID: Error
    = Error(sys::CKR_MECHANISM_PARAM_INVALID);
pub const R_OBJECT_HANDLE_INVALID: Error
    = Error(sys::CKR_OBJECT_HANDLE_INVALID);
pub const R_OPERATION_ACTIVE: Error
    = Error(sys::CKR_OPERATION_ACTIVE);
pub const R_OPERATION_NOT_INITIALIZED: Error
    = Error(sys::CKR_OPERATION_NOT_INITIALIZED);
pub const R_PIN_INCORRECT: Error = Error(sys::CKR_PIN_INCORRECT);
pub const R_PIN_INVALID: Error = Error(sys::CKR_PIN_INVALID);
pub const R_PIN_LEN_RANGE: Error = Error(sys::CKR_PIN_LEN_RANGE);
pub const R_PIN_EXPIRED: Error = Error(sys::CKR_PIN_EXPIRED);
pub const R_PIN_LOCKED: Error = Error(sys::CKR_PIN_LOCKED);
pub const R_SESSION_CLOSED: Error = Error(sys::CKR_SESSION_CLOSED);
pub const R_SESSION_COUNT: Error = Error(sys::CKR_SESSION_COUNT);
pub const R_SESSION_HANDLE_INVALID: Error
    = Error(sys::CKR_SESSION_HANDLE_INVALID);
pub const R_SESSION_PARALLEL_NOT_SUPPORTED: Error
    = Error(sys::CKR_SESSION_PARALLEL_NOT_SUPPORTED);
pub const R_SESSION_READ_ONLY: Error = Error(sys::CKR_SESSION_READ_ONLY);
pub const R_SESSION_EXISTS: Error = Error(sys::CKR_SESSION_EXISTS);
pub const R_SESSION_READ_ONLY_EXISTS: Error
    = Error(sys::CKR_SESSION_READ_ONLY_EXISTS);
pub const R_SESSION_READ_WRITE_SO_EXISTS: Error
    = Error(sys::CKR_SESSION_READ_WRITE_SO_EXISTS);
pub const R_SIGNATURE_INVALID: Error = Error(sys::CKR_SIGNATURE_INVALID);
pub const R_SIGNATURE_LEN_RANGE: Error
    = Error(sys::CKR_SIGNATURE_LEN_RANGE);
pub const R_TEMPLATE_INCOMPLETE: Error
    = Error(sys::CKR_TEMPLATE_INCOMPLETE);
pub const R_TEMPLATE_INCONSISTENT: Error
    = Error(sys::CKR_TEMPLATE_INCONSISTENT);
pub const R_TOKEN_NOT_PRESENT: Error = Error(sys::CKR_TOKEN_NOT_PRESENT);
pub const R_TOKEN_NOT_RECOGNIZED: Error
    = Error(sys::CKR_TOKEN_NOT_RECOGNIZED);
pub const R_TOKEN_WRITE_PROTECTED: Error
    = Error(sys::CKR_TOKEN_WRITE_PROTECTED);
pub const R_UNWRAPPING_KEY_HANDLE_INVALID: Error
    = Error(sys::CKR_UNWRAPPING_KEY_HANDLE_INVALID);
pub const R_UNWRAPPING_KEY_SIZE_RANGE: Error
    = Error(sys::CKR_UNWRAPPING_KEY_SIZE_RANGE);
pub const R_UNWRAPPING_KEY_TYPE_INCONSISTENT: Error
    = Error(sys::CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT);
pub const R_USER_ALREADY_LOGGED_IN: Error
    = Error(sys::CKR_USER_ALREADY_LOGGED_IN);
pub const R_USER_NOT_LOGGED_IN: Error
    = Error(sys::CKR_USER_NOT_LOGGED_IN);
pub const R_USER_PIN_NOT_INITIALIZED: Error
    = Error(sys::CKR_USER_PIN_NOT_INITIALIZED);
pub const R_USER_TYPE_INVALID: Error = Error(sys::CKR_USER_TYPE_INVALID);
pub const R_USER_ANOTHER_ALREADY_LOGGED_IN: Error
    = Error(sys::CKR_USER_ANOTHER_ALREADY_LOGGED_IN);
pub const R_USER_TOO_MANY_TYPES: Error = Error(sys::CKR_USER_TOO_MANY_TYPES);
pub const R_WRAPPED_KEY_INVALID: Error = Error(sys::CKR_WRAPPED_KEY_INVALID);
pub const R_WRAPPED_KEY_LEN_RANGE: Error
    = Error(sys::CKR_WRAPPED_KEY_LEN_RANGE);
pub const R_WRAPPING_KEY_HANDLE_INVALID: Error
    = Error(sys::CKR_WRAPPING_KEY_HANDLE_INVALID);
pub const R_WRAPPING_KEY_SIZE_RANGE: Error
    = Error(sys::CKR_WRAPPING_KEY_SIZE_RANGE);
pub const R_WRAPPING_KEY_TYPE_INCONSISTENT: Error
    = Error(sys::CKR_WRAPPING_KEY_TYPE_INCONSISTENT);
pub const R_RANDOM_SEED_NOT_SUPPORTED: Error
    = Error(sys::CKR_RANDOM_SEED_NOT_SUPPORTED);
pub const R_RANDOM_NO_RNG: Error = Error(sys::CKR_RANDOM_NO_RNG);
pub const R_DOMAIN_PARAMS_INVALID: Error
    = Error(sys::CKR_DOMAIN_PARAMS_INVALID);
pub const R_CURVE_NOT_SUPPORTED: Error
    = Error(sys::CKR_CURVE_NOT_SUPPORTED);
pub const R_BUFFER_TOO_SMALL: Error = Error(sys::CKR_BUFFER_TOO_SMALL);
pub const R_SAVED_STATE_INVALID: Error = Error(sys::CKR_SAVED_STATE_INVALID);
pub const R_INFORMATION_SENSITIVE: Error
    = Error(sys::CKR_INFORMATION_SENSITIVE);
pub const R_STATE_UNSAVEABLE: Error
    = Error(sys::CKR_STATE_UNSAVEABLE);
pub const R_CRYPTOKI_NOT_INITIALIZED: Error
    = Error(sys::CKR_CRYPTOKI_NOT_INITIALIZED);
pub const R_CRYPTOKI_ALREADY_INITIALIZED: Error
    = Error(sys::CKR_CRYPTOKI_ALREADY_INITIALIZED);
pub const R_MUTEX_BAD: Error = Error(sys::CKR_MUTEX_BAD);
pub const R_MUTEX_NOT_LOCKED: Error = Error(sys::CKR_MUTEX_NOT_LOCKED);
pub const R_NEW_PIN_MODE: Error = Error(sys::CKR_NEW_PIN_MODE);
pub const R_NEXT_OTP: Error = Error(sys::CKR_NEXT_OTP);
pub const R_EXCEEDED_MAX_ITERATIONS: Error
    = Error(sys::CKR_EXCEEDED_MAX_ITERATIONS);
pub const R_FIPS_SELF_TEST_FAILED: Error
    = Error(sys::CKR_FIPS_SELF_TEST_FAILED);
pub const R_LIBRARY_LOAD_FAILED: Error
    = Error(sys::CKR_LIBRARY_LOAD_FAILED);
pub const R_PIN_TOO_WEAK: Error
    = Error(sys::CKR_PIN_TOO_WEAK);
pub const R_PUBLIC_KEY_INVALID: Error
    = Error(sys::CKR_PUBLIC_KEY_INVALID);
pub const R_FUNCTION_REJECTED: Error = Error(sys::CKR_FUNCTION_REJECTED);


//--- From

impl From<sys::CK_RV> for Error {
    fn from(err: sys::CK_RV) -> Self {
        Error(err)
    }
}

impl From<Error> for sys::CK_RV {
    fn from(err: Error) -> Self {
        err.0
    }
}


//--- Error

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            R_OK => "CKR_OK",
            R_CANCEL => "CKR_CANCEL",
            R_HOST_MEMORY => "CKR_HOST_MEMORY",
            R_SLOT_ID_INVALID => "CKR_SLOT_ID_INVALID",

            R_GENERAL_ERROR => "CKR_GENERAL_ERROR",
            R_FUNCTION_FAILED => "CKR_FUNCTION_FAILED",

            R_ARGUMENTS_BAD => "CKR_ARGUMENTS_BAD",
            R_NO_EVENT => "CKR_NO_EVENT",
            R_NEED_TO_CREATE_THREADS => "CKR_NEED_TO_CREATE_THREADS",
            R_CANT_LOCK => "CKR_CANT_LOCK",

            R_ATTRIBUTE_READ_ONLY => "CKR_ATTRIBUTE_READ_ONLY",
            R_ATTRIBUTE_SENSITIVE => "CKR_ATTRIBUTE_SENSITIVE",
            R_ATTRIBUTE_TYPE_INVALID => "CKR_ATTRIBUTE_TYPE_INVALID",
            R_ATTRIBUTE_VALUE_INVALID => "CKR_ATTRIBUTE_VALUE_INVALID",

            R_ACTION_PROHIBITED => "CKR_ACTION_PROHIBITED",

            R_DATA_INVALID => "CKR_DATA_INVALID",
            R_DATA_LEN_RANGE => "CKR_DATA_LEN_RANGE",
            R_DEVICE_ERROR => "CKR_DEVICE_ERROR",
            R_DEVICE_MEMORY => "CKR_DEVICE_MEMORY",
            R_DEVICE_REMOVED => "CKR_DEVICE_REMOVED",
            R_ENCRYPTED_DATA_INVALID => "CKR_ENCRYPTED_DATA_INVALID",
            R_ENCRYPTED_DATA_LEN_RANGE
                => "CKR_ENCRYPTED_DATA_LEN_RANGE",
            R_FUNCTION_CANCELED => "CKR_FUNCTION_CANCELED",
            R_FUNCTION_NOT_PARALLEL => "CKR_FUNCTION_NOT_PARALLEL",

            R_FUNCTION_NOT_SUPPORTED => "CKR_FUNCTION_NOT_SUPPORTED",

            R_KEY_HANDLE_INVALID => "CKR_KEY_HANDLE_INVALID",

            R_KEY_SIZE_RANGE => "CKR_KEY_SIZE_RANGE",
            R_KEY_TYPE_INCONSISTENT => "CKR_KEY_TYPE_INCONSISTENT",

            R_KEY_NOT_NEEDED => "CKR_KEY_NOT_NEEDED",
            R_KEY_CHANGED => "CKR_KEY_CHANGED",
            R_KEY_NEEDED => "CKR_KEY_NEEDED",
            R_KEY_INDIGESTIBLE => "CKR_KEY_INDIGESTIBLE",
            R_KEY_FUNCTION_NOT_PERMITTED
                => "CKR_KEY_FUNCTION_NOT_PERMITTED",
            R_KEY_NOT_WRAPPABLE => "CKR_KEY_NOT_WRAPPABLE",
            R_KEY_UNEXTRACTABLE => "CKR_KEY_UNEXTRACTABLE",

            R_MECHANISM_INVALID => "CKR_MECHANISM_INVALID",
            R_MECHANISM_PARAM_INVALID => "CKR_MECHANISM_PARAM_INVALID",

            R_OBJECT_HANDLE_INVALID => "CKR_OBJECT_HANDLE_INVALID",
            R_OPERATION_ACTIVE => "CKR_OPERATION_ACTIVE",
            R_OPERATION_NOT_INITIALIZED
                => "CKR_OPERATION_NOT_INITIALIZED",
            R_PIN_INCORRECT => "CKR_PIN_INCORRECT",
            R_PIN_INVALID => "CKR_PIN_INVALID",
            R_PIN_LEN_RANGE => "CKR_PIN_LEN_RANGE",

            R_PIN_EXPIRED => "CKR_PIN_EXPIRED",
            R_PIN_LOCKED => "CKR_PIN_LOCKED",

            R_SESSION_CLOSED => "CKR_SESSION_CLOSED",
            R_SESSION_COUNT => "CKR_SESSION_COUNT",
            R_SESSION_HANDLE_INVALID => "CKR_SESSION_HANDLE_INVALID",
            R_SESSION_PARALLEL_NOT_SUPPORTED
                => "CKR_SESSION_PARALLEL_NOT_SUPPORTED",
            R_SESSION_READ_ONLY => "CKR_SESSION_READ_ONLY",
            R_SESSION_EXISTS => "CKR_SESSION_EXISTS",

            R_SESSION_READ_ONLY_EXISTS => "CKR_SESSION_READ_ONLY_EXISTS",
            R_SESSION_READ_WRITE_SO_EXISTS
                => "CKR_SESSION_READ_WRITE_SO_EXISTS",

            R_SIGNATURE_INVALID => "CKR_SIGNATURE_INVALID",
            R_SIGNATURE_LEN_RANGE => "CKR_SIGNATURE_LEN_RANGE",
            R_TEMPLATE_INCOMPLETE => "CKR_TEMPLATE_INCOMPLETE",
            R_TEMPLATE_INCONSISTENT => "CKR_TEMPLATE_INCONSISTENT",
            R_TOKEN_NOT_PRESENT => "CKR_TOKEN_NOT_PRESENT",
            R_TOKEN_NOT_RECOGNIZED => "CKR_TOKEN_NOT_RECOGNIZED",
            R_TOKEN_WRITE_PROTECTED => "CKR_TOKEN_WRITE_PROTECTED",
            R_UNWRAPPING_KEY_HANDLE_INVALID
                => "CKR_UNWRAPPING_KEY_HANDLE_INVALID",
            R_UNWRAPPING_KEY_SIZE_RANGE
                => "CKR_UNWRAPPING_KEY_SIZE_RANGE",
            R_UNWRAPPING_KEY_TYPE_INCONSISTENT
                => "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT",
            R_USER_ALREADY_LOGGED_IN => "CKR_USER_ALREADY_LOGGED_IN",
            R_USER_NOT_LOGGED_IN => "CKR_USER_NOT_LOGGED_IN",
            R_USER_PIN_NOT_INITIALIZED
                => "CKR_USER_PIN_NOT_INITIALIZED",
            R_USER_TYPE_INVALID => "CKR_USER_TYPE_INVALID",

            R_USER_ANOTHER_ALREADY_LOGGED_IN
                => "CKR_USER_ANOTHER_ALREADY_LOGGED_IN",
            R_USER_TOO_MANY_TYPES => "CKR_USER_TOO_MANY_TYPES",

            R_WRAPPED_KEY_INVALID => "CKR_WRAPPED_KEY_INVALID",
            R_WRAPPED_KEY_LEN_RANGE => "CKR_WRAPPED_KEY_LEN_RANGE",
            R_WRAPPING_KEY_HANDLE_INVALID
                => "CKR_WRAPPING_KEY_HANDLE_INVALID",
            R_WRAPPING_KEY_SIZE_RANGE
                => "CKR_WRAPPING_KEY_SIZE_RANGE",
            R_WRAPPING_KEY_TYPE_INCONSISTENT
                => "CKR_WRAPPING_KEY_TYPE_INCONSISTENT",
            R_RANDOM_SEED_NOT_SUPPORTED
                => "CKR_RANDOM_SEED_NOT_SUPPORTED",

            R_RANDOM_NO_RNG => "CKR_RANDOM_NO_RNG",

            R_DOMAIN_PARAMS_INVALID => "CKR_DOMAIN_PARAMS_INVALID",

            R_CURVE_NOT_SUPPORTED => "CKR_CURVE_NOT_SUPPORTED",

            R_BUFFER_TOO_SMALL => "CKR_BUFFER_TOO_SMALL",
            R_SAVED_STATE_INVALID => "CKR_SAVED_STATE_INVALID",
            R_INFORMATION_SENSITIVE => "CKR_INFORMATION_SENSITIVE",
            R_STATE_UNSAVEABLE => "CKR_STATE_UNSAVEABLE",

            R_CRYPTOKI_NOT_INITIALIZED
                => "CKR_CRYPTOKI_NOT_INITIALIZED",
            R_CRYPTOKI_ALREADY_INITIALIZED
                => "CKR_CRYPTOKI_ALREADY_INITIALIZED",
            R_MUTEX_BAD => "CKR_MUTEX_BAD",
            R_MUTEX_NOT_LOCKED => "CKR_MUTEX_NOT_LOCKED",

            R_NEW_PIN_MODE => "CKR_NEW_PIN_MODE",
            R_NEXT_OTP => "CKR_NEXT_OTP",

            R_EXCEEDED_MAX_ITERATIONS => "CKR_EXCEEDED_MAX_ITERATIONS",
            R_FIPS_SELF_TEST_FAILED => "CKR_FIPS_SELF_TEST_FAILED",
            R_LIBRARY_LOAD_FAILED => "CKR_LIBRARY_LOAD_FAILED",
            R_PIN_TOO_WEAK => "CKR_PIN_TOO_WEAK",
            R_PUBLIC_KEY_INVALID => "CKR_PUBLIC_KEY_INVALID",

            R_FUNCTION_REJECTED => "CKR_FUNCTION_REJECTED",
            _ => "unknown error"
        }
    }
}


//--- Debug

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        error::Error::description(self).fmt(f)
    }
}


//--- Display

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        error::Error::description(self).fmt(f)
    }
}


//------------ LoadError -----------------------------------------------------

#[derive(Debug)]
pub enum LoadError {
    Ck(Error),
    Io(io::Error),
}

impl From<Error> for LoadError {
    fn from(err: Error) -> Self {
        LoadError::Ck(err)
    }
}

impl From<io::Error> for LoadError {
    fn from(err: io::Error) -> Self {
        LoadError::Io(err)
    }
}

impl From<LoadError> for io::Error {
    fn from(err: LoadError) -> Self {
        match err {
            LoadError::Ck(_) => err.into(),
            LoadError::Io(err) => err,
        }
    }
}

impl error::Error for LoadError {
    fn description(&self) -> &str {
        match *self {
            LoadError::Ck(ref err) => err.description(),
            LoadError::Io(ref err) => err.description(),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            LoadError::Ck(ref err) => Some(err),
            LoadError::Io(ref err) => Some(err)
        }
    }
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(error::Error::description(self))
    }
}

