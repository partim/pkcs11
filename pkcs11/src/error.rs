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
            sys::CKR_OK => "CKR_OK",
            sys::CKR_CANCEL => "CKR_CANCEL",
            sys::CKR_HOST_MEMORY => "CKR_HOST_MEMORY",
            sys::CKR_SLOT_ID_INVALID => "CKR_SLOT_ID_INVALID",

            sys::CKR_GENERAL_ERROR => "CKR_GENERAL_ERROR",
            sys::CKR_FUNCTION_FAILED => "CKR_FUNCTION_FAILED",

            sys::CKR_ARGUMENTS_BAD => "CKR_ARGUMENTS_BAD",
            sys::CKR_NO_EVENT => "CKR_NO_EVENT",
            sys::CKR_NEED_TO_CREATE_THREADS => "CKR_NEED_TO_CREATE_THREADS",
            sys::CKR_CANT_LOCK => "CKR_CANT_LOCK",

            sys::CKR_ATTRIBUTE_READ_ONLY => "CKR_ATTRIBUTE_READ_ONLY",
            sys::CKR_ATTRIBUTE_SENSITIVE => "CKR_ATTRIBUTE_SENSITIVE",
            sys::CKR_ATTRIBUTE_TYPE_INVALID => "CKR_ATTRIBUTE_TYPE_INVALID",
            sys::CKR_ATTRIBUTE_VALUE_INVALID => "CKR_ATTRIBUTE_VALUE_INVALID",

            sys::CKR_ACTION_PROHIBITED => "CKR_ACTION_PROHIBITED",

            sys::CKR_DATA_INVALID => "CKR_DATA_INVALID",
            sys::CKR_DATA_LEN_RANGE => "CKR_DATA_LEN_RANGE",
            sys::CKR_DEVICE_ERROR => "CKR_DEVICE_ERROR",
            sys::CKR_DEVICE_MEMORY => "CKR_DEVICE_MEMORY",
            sys::CKR_DEVICE_REMOVED => "CKR_DEVICE_REMOVED",
            sys::CKR_ENCRYPTED_DATA_INVALID => "CKR_ENCRYPTED_DATA_INVALID",
            sys::CKR_ENCRYPTED_DATA_LEN_RANGE
                => "CKR_ENCRYPTED_DATA_LEN_RANGE",
            sys::CKR_FUNCTION_CANCELED => "CKR_FUNCTION_CANCELED",
            sys::CKR_FUNCTION_NOT_PARALLEL => "CKR_FUNCTION_NOT_PARALLEL",

            sys::CKR_FUNCTION_NOT_SUPPORTED => "CKR_FUNCTION_NOT_SUPPORTED",

            sys::CKR_KEY_HANDLE_INVALID => "CKR_KEY_HANDLE_INVALID",

            sys::CKR_KEY_SIZE_RANGE => "CKR_KEY_SIZE_RANGE",
            sys::CKR_KEY_TYPE_INCONSISTENT => "CKR_KEY_TYPE_INCONSISTENT",

            sys::CKR_KEY_NOT_NEEDED => "CKR_KEY_NOT_NEEDED",
            sys::CKR_KEY_CHANGED => "CKR_KEY_CHANGED",
            sys::CKR_KEY_NEEDED => "CKR_KEY_NEEDED",
            sys::CKR_KEY_INDIGESTIBLE => "CKR_KEY_INDIGESTIBLE",
            sys::CKR_KEY_FUNCTION_NOT_PERMITTED
                => "CKR_KEY_FUNCTION_NOT_PERMITTED",
            sys::CKR_KEY_NOT_WRAPPABLE => "CKR_KEY_NOT_WRAPPABLE",
            sys::CKR_KEY_UNEXTRACTABLE => "CKR_KEY_UNEXTRACTABLE",

            sys::CKR_MECHANISM_INVALID => "CKR_MECHANISM_INVALID",
            sys::CKR_MECHANISM_PARAM_INVALID => "CKR_MECHANISM_PARAM_INVALID",

            sys::CKR_OBJECT_HANDLE_INVALID => "CKR_OBJECT_HANDLE_INVALID",
            sys::CKR_OPERATION_ACTIVE => "CKR_OPERATION_ACTIVE",
            sys::CKR_OPERATION_NOT_INITIALIZED
                => "CKR_OPERATION_NOT_INITIALIZED",
            sys::CKR_PIN_INCORRECT => "CKR_PIN_INCORRECT",
            sys::CKR_PIN_INVALID => "CKR_PIN_INVALID",
            sys::CKR_PIN_LEN_RANGE => "CKR_PIN_LEN_RANGE",

            sys::CKR_PIN_EXPIRED => "CKR_PIN_EXPIRED",
            sys::CKR_PIN_LOCKED => "CKR_PIN_LOCKED",

            sys::CKR_SESSION_CLOSED => "CKR_SESSION_CLOSED",
            sys::CKR_SESSION_COUNT => "CKR_SESSION_COUNT",
            sys::CKR_SESSION_HANDLE_INVALID => "CKR_SESSION_HANDLE_INVALID",
            sys::CKR_SESSION_PARALLEL_NOT_SUPPORTED
                => "CKR_SESSION_PARALLEL_NOT_SUPPORTED",
            sys::CKR_SESSION_READ_ONLY => "CKR_SESSION_READ_ONLY",
            sys::CKR_SESSION_EXISTS => "CKR_SESSION_EXISTS",

            sys::CKR_SESSION_READ_ONLY_EXISTS => "CKR_SESSION_READ_ONLY_EXISTS",
            sys::CKR_SESSION_READ_WRITE_SO_EXISTS
                => "CKR_SESSION_READ_WRITE_SO_EXISTS",

            sys::CKR_SIGNATURE_INVALID => "CKR_SIGNATURE_INVALID",
            sys::CKR_SIGNATURE_LEN_RANGE => "CKR_SIGNATURE_LEN_RANGE",
            sys::CKR_TEMPLATE_INCOMPLETE => "CKR_TEMPLATE_INCOMPLETE",
            sys::CKR_TEMPLATE_INCONSISTENT => "CKR_TEMPLATE_INCONSISTENT",
            sys::CKR_TOKEN_NOT_PRESENT => "CKR_TOKEN_NOT_PRESENT",
            sys::CKR_TOKEN_NOT_RECOGNIZED => "CKR_TOKEN_NOT_RECOGNIZED",
            sys::CKR_TOKEN_WRITE_PROTECTED => "CKR_TOKEN_WRITE_PROTECTED",
            sys::CKR_UNWRAPPING_KEY_HANDLE_INVALID
                => "CKR_UNWRAPPING_KEY_HANDLE_INVALID",
            sys::CKR_UNWRAPPING_KEY_SIZE_RANGE
                => "CKR_UNWRAPPING_KEY_SIZE_RANGE",
            sys::CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT
                => "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT",
            sys::CKR_USER_ALREADY_LOGGED_IN => "CKR_USER_ALREADY_LOGGED_IN",
            sys::CKR_USER_NOT_LOGGED_IN => "CKR_USER_NOT_LOGGED_IN",
            sys::CKR_USER_PIN_NOT_INITIALIZED
                => "CKR_USER_PIN_NOT_INITIALIZED",
            sys::CKR_USER_TYPE_INVALID => "CKR_USER_TYPE_INVALID",

            sys::CKR_USER_ANOTHER_ALREADY_LOGGED_IN
                => "CKR_USER_ANOTHER_ALREADY_LOGGED_IN",
            sys::CKR_USER_TOO_MANY_TYPES => "CKR_USER_TOO_MANY_TYPES",

            sys::CKR_WRAPPED_KEY_INVALID => "CKR_WRAPPED_KEY_INVALID",
            sys::CKR_WRAPPED_KEY_LEN_RANGE => "CKR_WRAPPED_KEY_LEN_RANGE",
            sys::CKR_WRAPPING_KEY_HANDLE_INVALID
                => "CKR_WRAPPING_KEY_HANDLE_INVALID",
            sys::CKR_WRAPPING_KEY_SIZE_RANGE
                => "CKR_WRAPPING_KEY_SIZE_RANGE",
            sys::CKR_WRAPPING_KEY_TYPE_INCONSISTENT
                => "CKR_WRAPPING_KEY_TYPE_INCONSISTENT",
            sys::CKR_RANDOM_SEED_NOT_SUPPORTED
                => "CKR_RANDOM_SEED_NOT_SUPPORTED",

            sys::CKR_RANDOM_NO_RNG => "CKR_RANDOM_NO_RNG",

            sys::CKR_DOMAIN_PARAMS_INVALID => "CKR_DOMAIN_PARAMS_INVALID",

            sys::CKR_CURVE_NOT_SUPPORTED => "CKR_CURVE_NOT_SUPPORTED",

            sys::CKR_BUFFER_TOO_SMALL => "CKR_BUFFER_TOO_SMALL",
            sys::CKR_SAVED_STATE_INVALID => "CKR_SAVED_STATE_INVALID",
            sys::CKR_INFORMATION_SENSITIVE => "CKR_INFORMATION_SENSITIVE",
            sys::CKR_STATE_UNSAVEABLE => "CKR_STATE_UNSAVEABLE",

            sys::CKR_CRYPTOKI_NOT_INITIALIZED
                => "CKR_CRYPTOKI_NOT_INITIALIZED",
            sys::CKR_CRYPTOKI_ALREADY_INITIALIZED
                => "CKR_CRYPTOKI_ALREADY_INITIALIZED",
            sys::CKR_MUTEX_BAD => "CKR_MUTEX_BAD",
            sys::CKR_MUTEX_NOT_LOCKED => "CKR_MUTEX_NOT_LOCKED",

            sys::CKR_NEW_PIN_MODE => "CKR_NEW_PIN_MODE",
            sys::CKR_NEXT_OTP => "CKR_NEXT_OTP",

            sys::CKR_EXCEEDED_MAX_ITERATIONS => "CKR_EXCEEDED_MAX_ITERATIONS",
            sys::CKR_FIPS_SELF_TEST_FAILED => "CKR_FIPS_SELF_TEST_FAILED",
            sys::CKR_LIBRARY_LOAD_FAILED => "CKR_LIBRARY_LOAD_FAILED",
            sys::CKR_PIN_TOO_WEAK => "CKR_PIN_TOO_WEAK",
            sys::CKR_PUBLIC_KEY_INVALID => "CKR_PUBLIC_KEY_INVALID",

            sys::CKR_FUNCTION_REJECTED => "CKR_FUNCTION_REJECTED",
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
