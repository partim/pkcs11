//! CkError handling.

use std::{error, fmt, io};
use pkcs11_sys as sys;


//------------ CkError -------------------------------------------------------

/// A raw error from the underlying PKCS#11 library.
#[derive(Copy, Clone, Eq, Hash, PartialEq)]
pub struct CkError(sys::CK_RV);

impl CkError {
    pub fn error_code(&self) -> sys::CK_RV {
        self.0
    }
}


// Constants
pub const CKR_OK: CkError = CkError(sys::CKR_OK);
pub const CKR_CANCEL: CkError = CkError(sys::CKR_CANCEL);
pub const CKR_HOST_MEMORY: CkError = CkError(sys::CKR_HOST_MEMORY);
pub const CKR_SLOT_ID_INVALID: CkError = CkError(sys::CKR_SLOT_ID_INVALID);
pub const CKR_GENERAL_ERROR: CkError = CkError(sys::CKR_GENERAL_ERROR);
pub const CKR_FUNCTION_FAILED: CkError = CkError(sys::CKR_FUNCTION_FAILED);
pub const CKR_ARGUMENTS_BAD: CkError = CkError(sys::CKR_ARGUMENTS_BAD);
pub const CKR_NO_EVENT: CkError = CkError(sys::CKR_NO_EVENT);
pub const CKR_NEED_TO_CREATE_THREADS: CkError
    = CkError(sys::CKR_NEED_TO_CREATE_THREADS);
pub const CKR_CANT_LOCK: CkError = CkError(sys::CKR_CANT_LOCK);
pub const CKR_ATTRIBUTE_READ_ONLY : CkError
    = CkError(sys::CKR_ATTRIBUTE_READ_ONLY);
pub const CKR_ATTRIBUTE_SENSITIVE : CkError
    = CkError(sys::CKR_ATTRIBUTE_SENSITIVE);
pub const CKR_ATTRIBUTE_TYPE_INVALID : CkError
    = CkError(sys::CKR_ATTRIBUTE_TYPE_INVALID);
pub const CKR_ATTRIBUTE_VALUE_INVALID : CkError
    = CkError(sys::CKR_ATTRIBUTE_VALUE_INVALID);
pub const CKR_ACTION_PROHIBITED: CkError = CkError(sys::CKR_ACTION_PROHIBITED);
pub const CKR_DATA_INVALID: CkError = CkError(sys::CKR_DATA_INVALID);
pub const CKR_DATA_LEN_RANGE: CkError = CkError(sys::CKR_DATA_LEN_RANGE);
pub const CKR_DEVICE_ERROR: CkError = CkError(sys::CKR_DEVICE_ERROR);
pub const CKR_DEVICE_MEMORY: CkError = CkError(sys::CKR_DEVICE_MEMORY);
pub const CKR_DEVICE_REMOVED: CkError = CkError(sys::CKR_DEVICE_REMOVED);
pub const CKR_ENCRYPTED_DATA_INVALID : CkError
    = CkError(sys::CKR_ENCRYPTED_DATA_INVALID);
pub const CKR_ENCRYPTED_DATA_LEN_RANGE: CkError
    = CkError(sys::CKR_ENCRYPTED_DATA_LEN_RANGE);
pub const CKR_FUNCTION_CANCELED: CkError = CkError(sys::CKR_FUNCTION_CANCELED);
pub const CKR_FUNCTION_NOT_PARALLEL: CkError
    = CkError(sys::CKR_FUNCTION_NOT_PARALLEL);
pub const CKR_FUNCTION_NOT_SUPPORTED: CkError
    = CkError(sys::CKR_FUNCTION_NOT_SUPPORTED);
pub const CKR_KEY_HANDLE_INVALID: CkError = CkError(sys::CKR_KEY_HANDLE_INVALID);
pub const CKR_KEY_SIZE_RANGE: CkError = CkError(sys::CKR_KEY_SIZE_RANGE);
pub const CKR_KEY_TYPE_INCONSISTENT: CkError
    = CkError(sys::CKR_KEY_TYPE_INCONSISTENT);
pub const CKR_KEY_NOT_NEEDED: CkError = CkError(sys::CKR_KEY_NOT_NEEDED);
pub const CKR_KEY_CHANGED: CkError = CkError(sys::CKR_KEY_CHANGED);
pub const CKR_KEY_NEEDED: CkError = CkError(sys::CKR_KEY_NEEDED);
pub const CKR_KEY_INDIGESTIBLE: CkError = CkError(sys::CKR_KEY_INDIGESTIBLE);
pub const CKR_KEY_FUNCTION_NOT_PERMITTED: CkError
    = CkError(sys::CKR_KEY_FUNCTION_NOT_PERMITTED);
pub const CKR_KEY_NOT_WRAPPABLE: CkError = CkError(sys::CKR_KEY_NOT_WRAPPABLE);
pub const CKR_KEY_UNEXTRACTABLE: CkError = CkError(sys::CKR_KEY_UNEXTRACTABLE);
pub const CKR_MECHANISM_INVALID: CkError = CkError(sys::CKR_MECHANISM_INVALID);
pub const CKR_MECHANISM_PARAM_INVALID: CkError
    = CkError(sys::CKR_MECHANISM_PARAM_INVALID);
pub const CKR_OBJECT_HANDLE_INVALID: CkError
    = CkError(sys::CKR_OBJECT_HANDLE_INVALID);
pub const CKR_OPERATION_ACTIVE: CkError
    = CkError(sys::CKR_OPERATION_ACTIVE);
pub const CKR_OPERATION_NOT_INITIALIZED: CkError
    = CkError(sys::CKR_OPERATION_NOT_INITIALIZED);
pub const CKR_PIN_INCORRECT: CkError = CkError(sys::CKR_PIN_INCORRECT);
pub const CKR_PIN_INVALID: CkError = CkError(sys::CKR_PIN_INVALID);
pub const CKR_PIN_LEN_RANGE: CkError = CkError(sys::CKR_PIN_LEN_RANGE);
pub const CKR_PIN_EXPIRED: CkError = CkError(sys::CKR_PIN_EXPIRED);
pub const CKR_PIN_LOCKED: CkError = CkError(sys::CKR_PIN_LOCKED);
pub const CKR_SESSION_CLOSED: CkError = CkError(sys::CKR_SESSION_CLOSED);
pub const CKR_SESSION_COUNT: CkError = CkError(sys::CKR_SESSION_COUNT);
pub const CKR_SESSION_HANDLE_INVALID: CkError
    = CkError(sys::CKR_SESSION_HANDLE_INVALID);
pub const CKR_SESSION_PARALLEL_NOT_SUPPORTED: CkError
    = CkError(sys::CKR_SESSION_PARALLEL_NOT_SUPPORTED);
pub const CKR_SESSION_READ_ONLY: CkError = CkError(sys::CKR_SESSION_READ_ONLY);
pub const CKR_SESSION_EXISTS: CkError = CkError(sys::CKR_SESSION_EXISTS);
pub const CKR_SESSION_READ_ONLY_EXISTS: CkError
    = CkError(sys::CKR_SESSION_READ_ONLY_EXISTS);
pub const CKR_SESSION_READ_WRITE_SO_EXISTS: CkError
    = CkError(sys::CKR_SESSION_READ_WRITE_SO_EXISTS);
pub const CKR_SIGNATURE_INVALID: CkError = CkError(sys::CKR_SIGNATURE_INVALID);
pub const CKR_SIGNATURE_LEN_RANGE: CkError
    = CkError(sys::CKR_SIGNATURE_LEN_RANGE);
pub const CKR_TEMPLATE_INCOMPLETE: CkError
    = CkError(sys::CKR_TEMPLATE_INCOMPLETE);
pub const CKR_TEMPLATE_INCONSISTENT: CkError
    = CkError(sys::CKR_TEMPLATE_INCONSISTENT);
pub const CKR_TOKEN_NOT_PRESENT: CkError = CkError(sys::CKR_TOKEN_NOT_PRESENT);
pub const CKR_TOKEN_NOT_RECOGNIZED: CkError
    = CkError(sys::CKR_TOKEN_NOT_RECOGNIZED);
pub const CKR_TOKEN_WRITE_PROTECTED: CkError
    = CkError(sys::CKR_TOKEN_WRITE_PROTECTED);
pub const CKR_UNWRAPPING_KEY_HANDLE_INVALID: CkError
    = CkError(sys::CKR_UNWRAPPING_KEY_HANDLE_INVALID);
pub const CKR_UNWRAPPING_KEY_SIZE_RANGE: CkError
    = CkError(sys::CKR_UNWRAPPING_KEY_SIZE_RANGE);
pub const CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: CkError
    = CkError(sys::CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT);
pub const CKR_USER_ALREADY_LOGGED_IN: CkError
    = CkError(sys::CKR_USER_ALREADY_LOGGED_IN);
pub const CKR_USER_NOT_LOGGED_IN: CkError
    = CkError(sys::CKR_USER_NOT_LOGGED_IN);
pub const CKR_USER_PIN_NOT_INITIALIZED: CkError
    = CkError(sys::CKR_USER_PIN_NOT_INITIALIZED);
pub const CKR_USER_TYPE_INVALID: CkError = CkError(sys::CKR_USER_TYPE_INVALID);
pub const CKR_USER_ANOTHER_ALREADY_LOGGED_IN: CkError
    = CkError(sys::CKR_USER_ANOTHER_ALREADY_LOGGED_IN);
pub const CKR_USER_TOO_MANY_TYPES: CkError = CkError(sys::CKR_USER_TOO_MANY_TYPES);
pub const CKR_WRAPPED_KEY_INVALID: CkError = CkError(sys::CKR_WRAPPED_KEY_INVALID);
pub const CKR_WRAPPED_KEY_LEN_RANGE: CkError
    = CkError(sys::CKR_WRAPPED_KEY_LEN_RANGE);
pub const CKR_WRAPPING_KEY_HANDLE_INVALID: CkError
    = CkError(sys::CKR_WRAPPING_KEY_HANDLE_INVALID);
pub const CKR_WRAPPING_KEY_SIZE_RANGE: CkError
    = CkError(sys::CKR_WRAPPING_KEY_SIZE_RANGE);
pub const CKR_WRAPPING_KEY_TYPE_INCONSISTENT: CkError
    = CkError(sys::CKR_WRAPPING_KEY_TYPE_INCONSISTENT);
pub const CKR_RANDOM_SEED_NOT_SUPPORTED: CkError
    = CkError(sys::CKR_RANDOM_SEED_NOT_SUPPORTED);
pub const CKR_RANDOM_NO_RNG: CkError = CkError(sys::CKR_RANDOM_NO_RNG);
pub const CKR_DOMAIN_PARAMS_INVALID: CkError
    = CkError(sys::CKR_DOMAIN_PARAMS_INVALID);
pub const CKR_CURVE_NOT_SUPPORTED: CkError
    = CkError(sys::CKR_CURVE_NOT_SUPPORTED);
pub const CKR_BUFFER_TOO_SMALL: CkError = CkError(sys::CKR_BUFFER_TOO_SMALL);
pub const CKR_SAVED_STATE_INVALID: CkError = CkError(sys::CKR_SAVED_STATE_INVALID);
pub const CKR_INFORMATION_SENSITIVE: CkError
    = CkError(sys::CKR_INFORMATION_SENSITIVE);
pub const CKR_STATE_UNSAVEABLE: CkError
    = CkError(sys::CKR_STATE_UNSAVEABLE);
pub const CKR_CRYPTOKI_NOT_INITIALIZED: CkError
    = CkError(sys::CKR_CRYPTOKI_NOT_INITIALIZED);
pub const CKR_CRYPTOKI_ALREADY_INITIALIZED: CkError
    = CkError(sys::CKR_CRYPTOKI_ALREADY_INITIALIZED);
pub const CKR_MUTEX_BAD: CkError = CkError(sys::CKR_MUTEX_BAD);
pub const CKR_MUTEX_NOT_LOCKED: CkError = CkError(sys::CKR_MUTEX_NOT_LOCKED);
pub const CKR_NEW_PIN_MODE: CkError = CkError(sys::CKR_NEW_PIN_MODE);
pub const CKR_NEXT_OTP: CkError = CkError(sys::CKR_NEXT_OTP);
pub const CKR_EXCEEDED_MAX_ITERATIONS: CkError
    = CkError(sys::CKR_EXCEEDED_MAX_ITERATIONS);
pub const CKR_FIPS_SELF_TEST_FAILED: CkError
    = CkError(sys::CKR_FIPS_SELF_TEST_FAILED);
pub const CKR_LIBRARY_LOAD_FAILED: CkError
    = CkError(sys::CKR_LIBRARY_LOAD_FAILED);
pub const CKR_PIN_TOO_WEAK: CkError
    = CkError(sys::CKR_PIN_TOO_WEAK);
pub const CKR_PUBLIC_KEY_INVALID: CkError
    = CkError(sys::CKR_PUBLIC_KEY_INVALID);
pub const CKR_FUNCTION_REJECTED: CkError = CkError(sys::CKR_FUNCTION_REJECTED);


//--- From

impl From<sys::CK_RV> for CkError {
    fn from(err: sys::CK_RV) -> Self {
        CkError(err)
    }
}

impl From<CkError> for sys::CK_RV {
    fn from(err: CkError) -> Self {
        err.0
    }
}


//--- CkError

impl error::Error for CkError {
    fn description(&self) -> &str {
        match *self {
            CKR_OK => "CKR_OK",
            CKR_CANCEL => "CKR_CANCEL",
            CKR_HOST_MEMORY => "CKR_HOST_MEMORY",
            CKR_SLOT_ID_INVALID => "CKR_SLOT_ID_INVALID",

            CKR_GENERAL_ERROR => "CKR_GENERAL_ERROR",
            CKR_FUNCTION_FAILED => "CKR_FUNCTION_FAILED",

            CKR_ARGUMENTS_BAD => "CKR_ARGUMENTS_BAD",
            CKR_NO_EVENT => "CKR_NO_EVENT",
            CKR_NEED_TO_CREATE_THREADS => "CKR_NEED_TO_CREATE_THREADS",
            CKR_CANT_LOCK => "CKR_CANT_LOCK",

            CKR_ATTRIBUTE_READ_ONLY => "CKR_ATTRIBUTE_READ_ONLY",
            CKR_ATTRIBUTE_SENSITIVE => "CKR_ATTRIBUTE_SENSITIVE",
            CKR_ATTRIBUTE_TYPE_INVALID => "CKR_ATTRIBUTE_TYPE_INVALID",
            CKR_ATTRIBUTE_VALUE_INVALID => "CKR_ATTRIBUTE_VALUE_INVALID",

            CKR_ACTION_PROHIBITED => "CKR_ACTION_PROHIBITED",

            CKR_DATA_INVALID => "CKR_DATA_INVALID",
            CKR_DATA_LEN_RANGE => "CKR_DATA_LEN_RANGE",
            CKR_DEVICE_ERROR => "CKR_DEVICE_ERROR",
            CKR_DEVICE_MEMORY => "CKR_DEVICE_MEMORY",
            CKR_DEVICE_REMOVED => "CKR_DEVICE_REMOVED",
            CKR_ENCRYPTED_DATA_INVALID => "CKR_ENCRYPTED_DATA_INVALID",
            CKR_ENCRYPTED_DATA_LEN_RANGE
                => "CKR_ENCRYPTED_DATA_LEN_RANGE",
            CKR_FUNCTION_CANCELED => "CKR_FUNCTION_CANCELED",
            CKR_FUNCTION_NOT_PARALLEL => "CKR_FUNCTION_NOT_PARALLEL",

            CKR_FUNCTION_NOT_SUPPORTED => "CKR_FUNCTION_NOT_SUPPORTED",

            CKR_KEY_HANDLE_INVALID => "CKR_KEY_HANDLE_INVALID",

            CKR_KEY_SIZE_RANGE => "CKR_KEY_SIZE_RANGE",
            CKR_KEY_TYPE_INCONSISTENT => "CKR_KEY_TYPE_INCONSISTENT",

            CKR_KEY_NOT_NEEDED => "CKR_KEY_NOT_NEEDED",
            CKR_KEY_CHANGED => "CKR_KEY_CHANGED",
            CKR_KEY_NEEDED => "CKR_KEY_NEEDED",
            CKR_KEY_INDIGESTIBLE => "CKR_KEY_INDIGESTIBLE",
            CKR_KEY_FUNCTION_NOT_PERMITTED
                => "CKR_KEY_FUNCTION_NOT_PERMITTED",
            CKR_KEY_NOT_WRAPPABLE => "CKR_KEY_NOT_WRAPPABLE",
            CKR_KEY_UNEXTRACTABLE => "CKR_KEY_UNEXTRACTABLE",

            CKR_MECHANISM_INVALID => "CKR_MECHANISM_INVALID",
            CKR_MECHANISM_PARAM_INVALID => "CKR_MECHANISM_PARAM_INVALID",

            CKR_OBJECT_HANDLE_INVALID => "CKR_OBJECT_HANDLE_INVALID",
            CKR_OPERATION_ACTIVE => "CKR_OPERATION_ACTIVE",
            CKR_OPERATION_NOT_INITIALIZED
                => "CKR_OPERATION_NOT_INITIALIZED",
            CKR_PIN_INCORRECT => "CKR_PIN_INCORRECT",
            CKR_PIN_INVALID => "CKR_PIN_INVALID",
            CKR_PIN_LEN_RANGE => "CKR_PIN_LEN_RANGE",

            CKR_PIN_EXPIRED => "CKR_PIN_EXPIRED",
            CKR_PIN_LOCKED => "CKR_PIN_LOCKED",

            CKR_SESSION_CLOSED => "CKR_SESSION_CLOSED",
            CKR_SESSION_COUNT => "CKR_SESSION_COUNT",
            CKR_SESSION_HANDLE_INVALID => "CKR_SESSION_HANDLE_INVALID",
            CKR_SESSION_PARALLEL_NOT_SUPPORTED
                => "CKR_SESSION_PARALLEL_NOT_SUPPORTED",
            CKR_SESSION_READ_ONLY => "CKR_SESSION_READ_ONLY",
            CKR_SESSION_EXISTS => "CKR_SESSION_EXISTS",

            CKR_SESSION_READ_ONLY_EXISTS => "CKR_SESSION_READ_ONLY_EXISTS",
            CKR_SESSION_READ_WRITE_SO_EXISTS
                => "CKR_SESSION_READ_WRITE_SO_EXISTS",

            CKR_SIGNATURE_INVALID => "CKR_SIGNATURE_INVALID",
            CKR_SIGNATURE_LEN_RANGE => "CKR_SIGNATURE_LEN_RANGE",
            CKR_TEMPLATE_INCOMPLETE => "CKR_TEMPLATE_INCOMPLETE",
            CKR_TEMPLATE_INCONSISTENT => "CKR_TEMPLATE_INCONSISTENT",
            CKR_TOKEN_NOT_PRESENT => "CKR_TOKEN_NOT_PRESENT",
            CKR_TOKEN_NOT_RECOGNIZED => "CKR_TOKEN_NOT_RECOGNIZED",
            CKR_TOKEN_WRITE_PROTECTED => "CKR_TOKEN_WRITE_PROTECTED",
            CKR_UNWRAPPING_KEY_HANDLE_INVALID
                => "CKR_UNWRAPPING_KEY_HANDLE_INVALID",
            CKR_UNWRAPPING_KEY_SIZE_RANGE
                => "CKR_UNWRAPPING_KEY_SIZE_RANGE",
            CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT
                => "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT",
            CKR_USER_ALREADY_LOGGED_IN => "CKR_USER_ALREADY_LOGGED_IN",
            CKR_USER_NOT_LOGGED_IN => "CKR_USER_NOT_LOGGED_IN",
            CKR_USER_PIN_NOT_INITIALIZED
                => "CKR_USER_PIN_NOT_INITIALIZED",
            CKR_USER_TYPE_INVALID => "CKR_USER_TYPE_INVALID",

            CKR_USER_ANOTHER_ALREADY_LOGGED_IN
                => "CKR_USER_ANOTHER_ALREADY_LOGGED_IN",
            CKR_USER_TOO_MANY_TYPES => "CKR_USER_TOO_MANY_TYPES",

            CKR_WRAPPED_KEY_INVALID => "CKR_WRAPPED_KEY_INVALID",
            CKR_WRAPPED_KEY_LEN_RANGE => "CKR_WRAPPED_KEY_LEN_RANGE",
            CKR_WRAPPING_KEY_HANDLE_INVALID
                => "CKR_WRAPPING_KEY_HANDLE_INVALID",
            CKR_WRAPPING_KEY_SIZE_RANGE
                => "CKR_WRAPPING_KEY_SIZE_RANGE",
            CKR_WRAPPING_KEY_TYPE_INCONSISTENT
                => "CKR_WRAPPING_KEY_TYPE_INCONSISTENT",
            CKR_RANDOM_SEED_NOT_SUPPORTED
                => "CKR_RANDOM_SEED_NOT_SUPPORTED",

            CKR_RANDOM_NO_RNG => "CKR_RANDOM_NO_RNG",

            CKR_DOMAIN_PARAMS_INVALID => "CKR_DOMAIN_PARAMS_INVALID",

            CKR_CURVE_NOT_SUPPORTED => "CKR_CURVE_NOT_SUPPORTED",

            CKR_BUFFER_TOO_SMALL => "CKR_BUFFER_TOO_SMALL",
            CKR_SAVED_STATE_INVALID => "CKR_SAVED_STATE_INVALID",
            CKR_INFORMATION_SENSITIVE => "CKR_INFORMATION_SENSITIVE",
            CKR_STATE_UNSAVEABLE => "CKR_STATE_UNSAVEABLE",

            CKR_CRYPTOKI_NOT_INITIALIZED
                => "CKR_CRYPTOKI_NOT_INITIALIZED",
            CKR_CRYPTOKI_ALREADY_INITIALIZED
                => "CKR_CRYPTOKI_ALREADY_INITIALIZED",
            CKR_MUTEX_BAD => "CKR_MUTEX_BAD",
            CKR_MUTEX_NOT_LOCKED => "CKR_MUTEX_NOT_LOCKED",

            CKR_NEW_PIN_MODE => "CKR_NEW_PIN_MODE",
            CKR_NEXT_OTP => "CKR_NEXT_OTP",

            CKR_EXCEEDED_MAX_ITERATIONS => "CKR_EXCEEDED_MAX_ITERATIONS",
            CKR_FIPS_SELF_TEST_FAILED => "CKR_FIPS_SELF_TEST_FAILED",
            CKR_LIBRARY_LOAD_FAILED => "CKR_LIBRARY_LOAD_FAILED",
            CKR_PIN_TOO_WEAK => "CKR_PIN_TOO_WEAK",
            CKR_PUBLIC_KEY_INVALID => "CKR_PUBLIC_KEY_INVALID",

            CKR_FUNCTION_REJECTED => "CKR_FUNCTION_REJECTED",
            _ => "unknown error"
        }
    }
}


//--- Debug

impl fmt::Debug for CkError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        error::Error::description(self).fmt(f)
    }
}


//--- Display

impl fmt::Display for CkError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        error::Error::description(self).fmt(f)
    }
}


//------------ LoadError -----------------------------------------------------

#[derive(Debug)]
pub enum LoadError {
    Ck(CkError),
    Io(io::Error),
}

impl From<CkError> for LoadError {
    fn from(err: CkError) -> Self {
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

