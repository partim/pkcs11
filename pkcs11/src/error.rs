//! An error from PKCS #11.

use std::{error, fmt};
use pkcs11_sys as sys;


//------------ KeyError ------------------------------------------------------

/// A key was not good enough.
#[derive(Copy, Clone)]
pub enum KeyError {
    /// The specified key is not allowed for the attempted operation.
    KeyFunctionNotPermitted,

    /// The specified key is not valid.
    KeyHandleInvalid,

    /// The size of the specified key is out of range for the operation.
    KeySizeRange,

    /// The specified key cannot be used for the given mechanism.
    KeyTypeInconsistent,
}

impl KeyError {
    pub fn from_rv(rv: sys::CK_RV) -> Option<Self> {
        match rv {
            sys::CKR_KEY_HANDLE_INVALID => Some(KeyError::KeyHandleInvalid),
            sys::CKR_KEY_SIZE_RANGE => Some(KeyError::KeySizeRange),
            sys::CKR_KEY_TYPE_INCONSISTENT
                => Some(KeyError::KeyTypeInconsistent),
            _ => None
        }
    }

    pub fn wrapping_from_rv(rv: sys::CK_RV) -> Option<Self> {
        match rv {
            sys::CKR_WRAPPING_KEY_HANDLE_INVALID
                => Some(KeyError::KeyHandleInvalid),
            sys::CKR_WRAPPING_KEY_SIZE_RANGE => Some(KeyError::KeySizeRange),
            sys::CKR_WRAPPING_KEY_TYPE_INCONSISTENT
                => Some(KeyError::KeyTypeInconsistent),
            _ => None
        }
    }

    pub fn unwrapping_from_rv(rv: sys::CK_RV) -> Option<Self> {
        match rv {
            sys::CKR_UNWRAPPING_KEY_HANDLE_INVALID
                => Some(KeyError::KeyHandleInvalid),
            sys::CKR_UNWRAPPING_KEY_SIZE_RANGE
                => Some(KeyError::KeySizeRange),
            sys::CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT
                => Some(KeyError::KeyTypeInconsistent),
            _ => None
        }
    }
}


//------------ MechanismError ------------------------------------------------

/// The selected mechanism is not good enough.
#[derive(Copy, Clone)]
pub enum MechanismError {
    /// The specified mechanism is invalid for this operation.
    MechanismInvalid,

    /// Invalid parameters were supplied for the mechanism for the operation.
    MechanismParamInvalid,
}

impl MechanismError {
    pub fn from_rv(rv: sys::CK_RV) -> Option<Self> {
        match rv {
            sys::CKR_MECHANISM_INVALID
                => Some(MechanismError::MechanismInvalid),
            sys::CKR_MECHANISM_PARAM_INVALID
                => Some(MechanismError::MechanismParamInvalid),
            _ => None
        }
    }
}


//------------ PermissionError -----------------------------------------------

/// A operation has failed due to lack of permissions.
///
/// This type lumps together all specific errors that happen because an
/// operation that would otherwise probably be fine failed because it was
/// forbidden either by configuration or policy.
#[derive(Copy, Clone)]
pub enum PermissionError {
    /// The requested action was prohibited.
    ///
    /// This is either because of policy reasons or because the action was 
    /// indeed not allowed for the referenced object.
    ActionProhibited,

    /// The requested information was considered sensitive.
    InformationSensitive,

    /// A PIN has expired.
    ///
    /// The operation can only be carried out once the PIN has been reset
    /// using the `set_pin()` function.
    PinExpired,

    /// The specified session is a read-only session.
    SessionReadOnly,

    /// The token is write-protected.
    TokenWriteProtected,

    /// The appropriate user was not logged in.
    UserNotLoggedIn,
}

impl PermissionError {
    pub fn from_rv(rv: sys::CK_RV) -> Option<Self> {
        match rv {
            sys::CKR_ACTION_PROHIBITED
                => Some(PermissionError::ActionProhibited),
            sys::CKR_INFORMATION_SENSITIVE
                => Some(PermissionError::InformationSensitive),
            sys::CKR_PIN_EXPIRED => Some(PermissionError::PinExpired),
            sys::CKR_SESSION_READ_ONLY
                => Some(PermissionError::SessionReadOnly),
            sys::CKR_TOKEN_WRITE_PROTECTED
                => Some(PermissionError::TokenWriteProtected),
            sys::CKR_USER_NOT_LOGGED_IN
                => Some(PermissionError::UserNotLoggedIn),
            _ => None,
        }
    }
}


//------------ SessionError --------------------------------------------------

/// An error happened while working with a session.
///
/// An error of this category means that the session in question is not
/// usable anymore. In order to progress, a new session needs to be created.
#[derive(Copy, Clone)]
pub enum SessionError {
    /// The session was invalid at the time that the function was invoked.
    ///
    /// This can happen if the session’s token is removed before the function
    /// invocation, since removing a token closes all sessions with it.
    SessionHandleInvalid,

    /// The session was closed during the execution of the function.
    SessionClosed,
}

impl SessionError {
    pub fn from_rv(rv: sys::CK_RV) -> Option<Self> {
        match rv {
            sys::CKR_SESSION_HANDLE_INVALID
                => Some(SessionError::SessionHandleInvalid),
            sys::CKR_SESSION_CLOSED => Some(SessionError::SessionClosed),
            _ => None
        }
    }
}


//------------ TemplateError -------------------------------------------------

/// A template supplied to a function was invalid.
#[derive(Copy, Clone)]
pub enum TemplateError {
    /// One of the attributes cannot be set or modified.
    AttributeReadOnly,

    /// One of the attributes had an invalid type specified. 
    AttributeTypeInvalid,

    /// One of the attributes had an invalid value.
    AttributeValueInvalid,

    /// One of the attributes specified a curve not supported by this token.
    CurveNotSupported,

    /// Invalid or unsupported domain parameters were supplied.
    DomainParamsInvalid,

    /// The template specified lacks some necessary attributes.
    TemplateIncomplete,

    /// The template specified has conflicting attributes. 
    TemplateInconsistent,
}

impl TemplateError {
    pub fn from_rv(rv: sys::CK_RV) -> Option<Self> {
        match rv {
            sys::CKR_ATTRIBUTE_READ_ONLY
                => Some(TemplateError::AttributeReadOnly),
            sys::CKR_ATTRIBUTE_TYPE_INVALID
                => Some(TemplateError::AttributeTypeInvalid),
            sys::CKR_ATTRIBUTE_VALUE_INVALID
                => Some(TemplateError::AttributeValueInvalid),
            sys::CKR_CURVE_NOT_SUPPORTED
                => Some(TemplateError::CurveNotSupported),
            sys::CKR_DOMAIN_PARAMS_INVALID
                => Some(TemplateError::DomainParamsInvalid),
            sys::CKR_TEMPLATE_INCOMPLETE
                => Some(TemplateError::TemplateIncomplete),
            sys::CKR_TEMPLATE_INCONSISTENT
                => Some(TemplateError::TemplateInconsistent),
            _ => None
        }
    }
}


//------------ TokenError ---------------------------------------------------

/// An error happened with the library or token.
///
/// An error of this type means that something reasonably bad or unforeseen
/// has happened that continuing may not really be advisable.
#[derive(Copy, Clone)]
pub enum TokenError {
    /// Some horrible, unrecoverable error has occurred.
    ///
    /// In the worst case, it is possible that the function only partially
    /// succeeded, and that the computer and/or token is in an inconsistent
    /// state.
    GeneralError,

    /// Insufficient memory on the host computer.
    ///
    /// The computer that the Cryptoki library is running on has insufficient
    /// memory to perform the requested function.
    HostMemory,

    /// The requested function could not be performed.
    ///
    /// If the function in question was a session, more detailed information
    /// may be available through the session info’s device error field.
    FunctionFailed,

    /// The token does not have sufficient memory to perform the function.
    DeviceMemory,

    /// Some problem has occurred with the token and/or slot.
    DeviceError,

    /// The token was not present at the time the function was invoked.
    TokenNotPresent,

    /// The token was removed from its slot during execution of the function.
    DeviceRemoved,

    // Further errors specified to happen for functions that we can put here:
    //
    // CKR_FUNCTION_CANCELED

    /// The library or slot does not recognize the token in the slot.
    TokenNotRecognized,

    /// Some other error has occurred.
    ///
    /// This error means that the underlying library has returned an error
    /// that wasn’t allowed for this function by the standard. As this
    /// means that the state of library and token isn’t well defined anymore,
    /// it might be advisable to give up.
    Other(CryptokiError),
}

impl From<CryptokiError> for TokenError {
    fn from(err: CryptokiError) -> Self {
        match err.0 {
            sys::CKR_DEVICE_ERROR => TokenError::DeviceError,
            sys::CKR_DEVICE_MEMORY => TokenError::DeviceMemory,
            sys::CKR_DEVICE_REMOVED => TokenError::DeviceRemoved,
            sys::CKR_FUNCTION_FAILED => TokenError::FunctionFailed,
            sys::CKR_GENERAL_ERROR => TokenError::GeneralError,
            sys::CKR_HOST_MEMORY => TokenError::HostMemory,
            sys::CKR_TOKEN_NOT_PRESENT => TokenError::TokenNotPresent,
            sys::CKR_TOKEN_NOT_RECOGNIZED => TokenError::TokenNotRecognized,
            _ => TokenError::Other(err)
        }
    }
}

impl From<sys::CK_RV> for TokenError {
    fn from(err: sys::CK_RV) -> Self {
        CryptokiError::from(err).into()
    }
}


//------------ CryptokiError ------------------------------------------------

/// A raw error from the underlying PKCS#11 library.
#[derive(Copy, Clone)]
pub struct CryptokiError(sys::CK_RV);

impl CryptokiError {
    pub fn error_code(&self) -> sys::CK_RV {
        self.0
    }
}


//--- From

impl From<sys::CK_RV> for CryptokiError {
    fn from(err: sys::CK_RV) -> Self {
        CryptokiError(err)
    }
}

impl From<CryptokiError> for sys::CK_RV {
    fn from(err: CryptokiError) -> Self {
        err.0
    }
}


//--- Error

impl error::Error for CryptokiError {
    fn description(&self) -> &str {
        match self.0 {
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


//--- Debug

impl fmt::Debug for CryptokiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        error::Error::description(self).fmt(f)
    }
}


//--- Display

impl fmt::Display for CryptokiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        error::Error::description(self).fmt(f)
    }
}

