//! Error handling.

use std::{error, fmt, io};
use pkcs11_sys as sys;


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


//============ Error Categories ==============================================

//------------ KeyError ------------------------------------------------------

/// A key was not good enough.
#[derive(Copy, Clone, Debug)]
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
#[derive(Copy, Clone, Debug)]
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
#[derive(Copy, Clone, Debug)]
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
#[derive(Copy, Clone, Debug)]
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
#[derive(Copy, Clone, Debug)]
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
#[derive(Copy, Clone, Debug)]
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


//============ Method-specific Errors ========================================

//------------ LoadError -----------------------------------------------------

#[derive(Debug)]
pub enum LoadError {
    Token(TokenError),
    Io(io::Error),
}

impl From<TokenError> for LoadError {
    fn from(err: TokenError) -> Self {
        LoadError::Token(err)
    }
}

impl From<io::Error> for LoadError {
    fn from(err: io::Error) -> Self {
        LoadError::Io(err)
    }
}


//------------ SlotAccessError -----------------------------------------------

/// An error happened during functions that query slot-related information.
#[derive(Copy, Clone, Debug)]
pub enum SlotAccessError {
    /// The slot ID given does not refer to an exisiting slot.
    SlotIdInvalid,

    /// A token error occured.
    Token(TokenError)
}

impl From<sys::CK_RV> for SlotAccessError {
    fn from(err: sys::CK_RV) -> Self {
        match err {
            sys::CKR_SLOT_ID_INVALID => SlotAccessError::SlotIdInvalid,
            _ => SlotAccessError::Token(err.into())
        }
    }
}


//------------ GetMechanismInfoError -----------------------------------------

/// An error happened during the `Cryptoki::get_mechanism_info()` method.
#[derive(Copy, Clone, Debug)]
pub enum GetMechanismInfoError {
    /// The mechanism type given is not supported by the token.
    InvalidMechanism,

    /// The slot ID given does not refer to an exisiting slot.
    SlotIdInvalid,

    /// A token error occured.
    Token(TokenError)
}

impl From<sys::CK_RV> for GetMechanismInfoError {
    fn from(err: sys::CK_RV) -> Self {
        match err {
            sys::CKR_MECHANISM_INVALID
                => GetMechanismInfoError::InvalidMechanism,
            sys::CKR_SLOT_ID_INVALID => GetMechanismInfoError::SlotIdInvalid,
            _ => GetMechanismInfoError::Token(err.into())
        }
    }
}


//------------ InitTokenError -----------------------------------------------

/// An error happened during the `Cryptoki::init_token()` method.
#[derive(Copy, Clone, Debug)]
pub enum InitTokenError {
    /// The label is not exactly 32 bytes long.
    LabelInvalid,

    /// The specified PIN does not match the PIN stored in the token.
    PinIncorrect,

    /// The PIN is locked, e.g. after too many failed attempts.
    PinLocked,

    /// The token cannot be initialized because a session with it exists.
    SessionExists,

    /// The slot ID given does not refer to an exisiting slot.
    SlotIdInvalid,

    /// The token cannot be initialized because it is write-protected.
    TokenWriteProtected,

    /// A token error occured.
    Token(TokenError)
}

impl From<sys::CK_RV> for InitTokenError {
    fn from(err: sys::CK_RV) -> Self {
        match err {
            sys::CKR_PIN_INCORRECT => InitTokenError::PinIncorrect,
            sys::CKR_PIN_LOCKED => InitTokenError::PinLocked,
            sys::CKR_SESSION_EXISTS => InitTokenError::SessionExists,
            sys::CKR_SLOT_ID_INVALID => InitTokenError::SlotIdInvalid,
            sys::CKR_TOKEN_WRITE_PROTECTED
                => InitTokenError::TokenWriteProtected,
            _ => InitTokenError::Token(err.into())
        }
    }
}


//------------ SetPinError --------------------------------------------------

/// An error happened while initializing or setting a PIN.
#[derive(Clone, Copy, Debug)]
pub enum SetPinError {
    /// The specified PIN has invalid characters in it.
    PinInvalid,

    /// The specified PIN does not match the PIN stored in the token.
    PinIncorrect,

    /// The specified PIN is too long or too short.
    PinLenRange,

    /// The PIN is locked, e.g. after too many failed attempts.
    PinLocked,

    /// A read-only error occurred.
    Permission(PermissionError),

    /// A session error occurred.
    Session(SessionError),

    /// A token error occurred.
    Token(TokenError)
}

impl From<sys::CK_RV> for SetPinError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = PermissionError::from_rv(err) {
            SetPinError::Permission(err)
        }
        else if let Some(err) = SessionError::from_rv(err) {
            SetPinError::Session(err)
        }
        else {
            match err {
                sys::CKR_PIN_INVALID => SetPinError::PinInvalid,
                sys::CKR_PIN_INCORRECT => SetPinError::PinIncorrect,
                sys::CKR_PIN_LEN_RANGE => SetPinError::PinLenRange,
                sys::CKR_PIN_LOCKED => SetPinError::PinLocked,
                _ => SetPinError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ OpenSessionError ----------------------------------------------

/// An error happened while opening a session.
#[derive(Clone, Copy, Debug)]
pub enum OpenSessionError {
    /// Either too many sessions or too many read/write sessions already open.
    SessionCount,
    
    /// A read/write SO session already exists.
    ///
    /// This prevents any further read-only sessions.
    SessionReadWriteSoExists,

    /// The slot ID given does not refer to an exisiting slot.
    SlotIdInvalid,

    /// A read-only error occurred.
    Permission(PermissionError),

    /// A token error occurred.
    Token(TokenError)
}

impl From<sys::CK_RV> for OpenSessionError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = PermissionError::from_rv(err) {
            OpenSessionError::Permission(err)
        }
        else {
            match err {
                sys::CKR_SESSION_COUNT => OpenSessionError::SessionCount,
                sys::CKR_SESSION_READ_WRITE_SO_EXISTS
                    => OpenSessionError::SessionReadWriteSoExists,
                sys::CKR_SLOT_ID_INVALID => OpenSessionError::SlotIdInvalid,
                _ => OpenSessionError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ SessionAccessError --------------------------------------------

/// An error happened when closing a session.
#[derive(Copy, Clone, Debug)]
pub enum SessionAccessError {
    /// A session error occurred.
    Session(SessionError),

    /// A token error occurred.
    Token(TokenError),
}

impl From<sys::CK_RV> for SessionAccessError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = SessionError::from_rv(err) {
            SessionAccessError::Session(err)
        }
        else {
            SessionAccessError::Token(TokenError::from(err))
        }
    }
}


//------------ GetOperationStateError ---------------------------------------

/// An error happened when trying to get the operation state.
#[derive(Clone, Copy, Debug)]
pub enum GetOperationStateError {
    /// The output is too large to fit in the supplied buffer.
    BufferTooSmall,

    /// There is no operation ongoing that would allow saving state.
    OperationNotInitialized,

    /// The operation state cannot be saved for some reason.
    StateUnsaveable,

    /// A session error occured.
    Session(SessionError),

    /// A token error occurred.
    Token(TokenError)
}

impl From<sys::CK_RV> for GetOperationStateError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = SessionError::from_rv(err) {
            GetOperationStateError::Session(err)
        }
        else {
            match err {
                sys::CKR_BUFFER_TOO_SMALL
                    => GetOperationStateError::BufferTooSmall,
                sys::CKR_OPERATION_NOT_INITIALIZED
                    => GetOperationStateError::OperationNotInitialized,
                sys::CKR_STATE_UNSAVEABLE
                    => GetOperationStateError::StateUnsaveable,
                _ => GetOperationStateError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ SetOperationStateError ---------------------------------------

/// An error happened while trying to set the operation state.
#[derive(Clone, Copy, Debug)]
pub enum SetOperationStateError {
    /// One of the keys specified is not the one used in the saved session.
    KeyChanged,

    /// One or both keys need to be supplied.
    KeyNeeded,

    /// An extraneous key was supplied.
    KeyNotNeeded,

    /// The supplied saved cryptographic operations state is invalid.
    SavedStateInvalid,

    /// A session error has occurred.
    Session(SessionError),

    /// A token error has occurred.
    Token(TokenError)
}

impl From<sys::CK_RV> for SetOperationStateError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = SessionError::from_rv(err) {
            SetOperationStateError::Session(err)
        }
        else {
            match err {
                sys::CKR_KEY_CHANGED => SetOperationStateError::KeyChanged,
                sys::CKR_KEY_NEEDED => SetOperationStateError::KeyNeeded,
                sys::CKR_KEY_NOT_NEEDED
                    => SetOperationStateError::KeyNotNeeded,
                sys::CKR_SAVED_STATE_INVALID
                    => SetOperationStateError::SavedStateInvalid,
                _ => SetOperationStateError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ LoginError ---------------------------------------------------

/// An error has occurred whil trying to log in.
// XXX Might be useful to break this into temporary and permanent errors.
#[derive(Clone, Copy, Debug)]
pub enum LoginError {
    /// A context specific login was not properly prepared.
    OperationNotInitialized,

    /// The specified PIN does not match the PIN stored in the token.
    PinIncorrect,

    /// The PIN is locked, e.g. after too many failed attempts.
    PinLocked,

    /// A read-only is open preventing the SO to log in.
    SessionReadOnlyExists,

    /// The specified user is already logged in.
    UserAlreadyLoggedIn,

    /// Another user is already logged in preventing this user to log in.
    UserAnotherAlreadyLoggedIn,

    /// The normal user’s PIN has not yet been initialized.
    UserPinNotInitialized,

    /// An attempt was made to have more distinct users simultaneously
    /// logged into the token than the token and/or library permits.
    UserTooManyTypes,

    /// A session error has occurred.
    Session(SessionError),

    /// A token error has occurred.
    Token(TokenError)
}

impl From<sys::CK_RV> for LoginError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = SessionError::from_rv(err) {
            LoginError::Session(err)
        }
        else {
            match err {
                sys::CKR_OPERATION_NOT_INITIALIZED
                    => LoginError::OperationNotInitialized,
                sys::CKR_PIN_INCORRECT => LoginError::PinIncorrect,
                sys::CKR_PIN_LOCKED => LoginError::PinLocked,
                sys::CKR_SESSION_READ_ONLY_EXISTS
                    => LoginError::SessionReadOnlyExists,
                sys::CKR_USER_ALREADY_LOGGED_IN
                    => LoginError::UserAlreadyLoggedIn,
                sys::CKR_USER_ANOTHER_ALREADY_LOGGED_IN
                    => LoginError::UserAnotherAlreadyLoggedIn,
                sys::CKR_USER_PIN_NOT_INITIALIZED
                    => LoginError::UserPinNotInitialized,
                sys::CKR_USER_TOO_MANY_TYPES => LoginError::UserTooManyTypes,
                _ => LoginError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ LogoutError ---------------------------------------------------

/// An error happened while logging out.
#[derive(Clone, Copy, Debug)]
pub enum LogoutError {
    /// A user is not logged in.
    UserNotLoggedIn,

    /// A session error occurred.
    Session(SessionError),

    /// A token error occurred.
    Token(TokenError)
}

impl From<sys::CK_RV> for LogoutError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = SessionError::from_rv(err) {
            LogoutError::Session(err)
        }
        else {
            match err {
                sys::CKR_USER_NOT_LOGGED_IN => LogoutError::UserNotLoggedIn,
                _ => LogoutError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ CreateObjectError ---------------------------------------------

/// An error happened when creating an object.
#[derive(Copy, Clone, Debug)]
pub enum CreateObjectError {
    Template(TemplateError),
    Permission(PermissionError),
    Session(SessionError),
    Token(TokenError),
}

impl From<sys::CK_RV> for CreateObjectError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = TemplateError::from_rv(err) {
            CreateObjectError::Template(err)
        }
        else if let Some(err) = PermissionError::from_rv(err) {
            CreateObjectError::Permission(err)
        }
        else if let Some(err) = SessionError::from_rv(err) {
            CreateObjectError::Session(err)
        }
        else {
            CreateObjectError::Token(TokenError::from(err))
        }
    }
}


//------------ CopyObjectError -----------------------------------------------

/// An error happened when copying an object.
#[derive(Copy, Clone, Debug)]
pub enum CopyObjectError {
    /// The specified object handle is not valid.
    ObjectHandleInvalid,

    Template(TemplateError),
    Permission(PermissionError),
    Session(SessionError),
    Token(TokenError),
}

impl From<sys::CK_RV> for CopyObjectError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = TemplateError::from_rv(err) {
            CopyObjectError::Template(err)
        }
        else if let Some(err) = PermissionError::from_rv(err) {
            CopyObjectError::Permission(err)
        }
        else if let Some(err) = SessionError::from_rv(err) {
            CopyObjectError::Session(err)
        }
        else {
            match err {
                sys::CKR_OBJECT_HANDLE_INVALID
                    => CopyObjectError::ObjectHandleInvalid,
                _ => CopyObjectError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ ObjectAccessError ---------------------------------------------

/// An error happened while trying to access an object.
#[derive(Copy, Clone, Debug)]
pub enum ObjectAccessError {
    /// The specified object handle is not valid.
    ObjectHandleInvalid,

    Permission(PermissionError),
    Session(SessionError),
    Token(TokenError),
}

impl From<sys::CK_RV> for ObjectAccessError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = PermissionError::from_rv(err) {
            ObjectAccessError::Permission(err)
        }
        else if let Some(err) = SessionError::from_rv(err) {
            ObjectAccessError::Session(err)
        }
        else {
            match err {
                sys::CKR_OBJECT_HANDLE_INVALID
                    => ObjectAccessError::ObjectHandleInvalid,
                _ => ObjectAccessError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ GetAttributeValueError ---------------------------------------

/// An error happened while trying to get attribute values.
#[derive(Clone, Copy, Debug)]
pub enum GetAttributeValueError {
    /// At least one of the attributes was considered sensitive.
    AttributeSensitive,

    /// At least one attribute type was not valid for the object refered to.
    AttributeTypeInvalid,

    /// For at least one attribute was the buffer supplied too small.
    BufferTooSmall,

    /// The object handle given was not valid.
    ObjectHandleInvalid,

    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for GetAttributeValueError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = SessionError::from_rv(err) {
            GetAttributeValueError::Session(err)
        }
        else {
            match err {
                sys::CKR_ATTRIBUTE_SENSITIVE
                    => GetAttributeValueError::AttributeSensitive,
                sys::CKR_ATTRIBUTE_TYPE_INVALID
                    => GetAttributeValueError::AttributeTypeInvalid,
                sys::CKR_BUFFER_TOO_SMALL
                    => GetAttributeValueError::BufferTooSmall,
                sys::CKR_OBJECT_HANDLE_INVALID
                    => GetAttributeValueError::ObjectHandleInvalid,
                _ => GetAttributeValueError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ FindObjectsInitError ------------------------------------------

/// An error happened while initializing a search for objects.
#[derive(Copy, Clone, Debug)]
pub enum FindObjectsInitError {
    /// A search operation is already ongoing within this session.
    OperationActive,

    Template(TemplateError),
    Permission(PermissionError),
    Session(SessionError),
    Token(TokenError),
}

impl From<sys::CK_RV> for FindObjectsInitError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = TemplateError::from_rv(err) {
            FindObjectsInitError::Template(err)
        }
        else if let Some(err) = PermissionError::from_rv(err) {
            FindObjectsInitError::Permission(err)
        }
        else if let Some(err) = SessionError::from_rv(err) {
            FindObjectsInitError::Session(err)
        }
        else {
            match err {
                sys::CKR_OPERATION_ACTIVE
                    => FindObjectsInitError::OperationActive,
                _ => FindObjectsInitError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ ContinuationError --------------------------------------------

/// An error happened during searching for objects.
#[derive(Clone, Copy, Debug)]
pub enum ContinuationError {
    /// The operation has not been previously initialized.
    OperationNotInitialized,

    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for ContinuationError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = SessionError::from_rv(err) {
            ContinuationError::Session(err)
        }
        else {
            match err {
                sys::CKR_OPERATION_NOT_INITIALIZED
                    => ContinuationError::OperationNotInitialized,
                _ => ContinuationError::Token(TokenError::from(err))
            }
        }
    }
}


//----------- CryptoInitError ------------------------------------------------

/// An error happened while initializing a crypto operation.
#[derive(Copy, Clone, Debug)]
pub enum CryptoInitError {
    /// An exclusive operation is already active on this session. 
    OperationActive,

    Key(KeyError),
    Mechanism(MechanismError),
    Permission(PermissionError),
    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for CryptoInitError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = KeyError::from_rv(err) {
            CryptoInitError::Key(err)
        }
        else if let Some(err) = MechanismError::from_rv(err) {
            CryptoInitError::Mechanism(err)
        }
        else if let Some(err) = PermissionError::from_rv(err) {
            CryptoInitError::Permission(err)
        }
        else if let Some(err) = SessionError::from_rv(err) {
            CryptoInitError::Session(err)
        }
        else {
            match err {
                sys::CKR_OPERATION_ACTIVE => CryptoInitError::OperationActive,
                _ => CryptoInitError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ PlaintextError ------------------------------------------------

/// An error happened while performing an operation with plaintext input.
#[derive(Clone, Copy, Debug)]
pub enum PlaintextError {
    /// The supplied buffer was too small.
    BufferTooSmall,

    /// The plaintext input data to a cryptographic operation is invalid.
    DataInvalid,

    /// The plaintext input data to a cryptographic operation has a bad length.
    ///
    /// Depending on the operation’s mechanism, this could mean that the
    /// plaintext data is too short, too long, or is not a multiple of some
    /// particular block size.
    DataLenRange,

    /// A crypto operation of this type has not been previously initialized.
    OperationNotInitialized,

    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for PlaintextError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = SessionError::from_rv(err) {
            PlaintextError::Session(err)
        }
        else {
            match err {
                sys::CKR_BUFFER_TOO_SMALL => PlaintextError::BufferTooSmall,
                sys::CKR_DATA_INVALID => PlaintextError::DataInvalid,
                sys::CKR_DATA_LEN_RANGE => PlaintextError::DataLenRange,
                sys::CKR_OPERATION_NOT_INITIALIZED
                    => PlaintextError::OperationNotInitialized,
                _ => PlaintextError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ PlaintextUpdateError ------------------------------------------

/// An error happened while performing an operation with plaintext input.
#[derive(Clone, Copy, Debug)]
pub enum PlaintextUpdateError {
    /// The plaintext input data to a cryptographic operation is invalid.
    DataInvalid,

    /// The plaintext input data to a cryptographic operation has a bad length.
    ///
    /// Depending on the operation’s mechanism, this could mean that the
    /// plaintext data is too short, too long, or is not a multiple of some
    /// particular block size.
    DataLenRange,

    /// A crypto operation of this type has not been previously initialized.
    OperationNotInitialized,

    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for PlaintextUpdateError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = SessionError::from_rv(err) {
            PlaintextUpdateError::Session(err)
        }
        else {
            match err {
                sys::CKR_DATA_INVALID => PlaintextUpdateError::DataInvalid,
                sys::CKR_DATA_LEN_RANGE => PlaintextUpdateError::DataLenRange,
                sys::CKR_OPERATION_NOT_INITIALIZED
                    => PlaintextUpdateError::OperationNotInitialized,
                _ => PlaintextUpdateError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ CiphertextError -----------------------------------------------

/// An error happened while performing an operation with ciphertext input.
#[derive(Clone, Copy, Debug)]
pub enum CiphertextError {
    /// The supplied buffer was too small.
    BufferTooSmall,

    /// The ciphertext input to a cryptographic operation is invalid.
    EncryptedDataInvalid,

    /// The ciphertext input to a cryptographic operation has a bad length.
    ///
    /// Depending on the operation’s mechanism, this could mean that the
    /// plaintext data is too short, too long, or is not a multiple of some
    /// particular block size.
    EncryptedDataLenRange,

    /// A crypto operation of this type has not been previously initialized.
    OperationNotInitialized,

    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for CiphertextError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = SessionError::from_rv(err) {
            CiphertextError::Session(err)
        }
        else {
            match err {
                sys::CKR_BUFFER_TOO_SMALL => CiphertextError::BufferTooSmall,
                sys::CKR_ENCRYPTED_DATA_INVALID
                    => CiphertextError::EncryptedDataInvalid,
                sys::CKR_ENCRYPTED_DATA_LEN_RANGE
                    => CiphertextError::EncryptedDataLenRange,
                sys::CKR_OPERATION_NOT_INITIALIZED
                    => CiphertextError::OperationNotInitialized,
                _ => CiphertextError::Token(TokenError::from(err))
            }
        }
    }
}


//----------- DigestInitError ------------------------------------------------

/// An error happened while initializing a digest operation.
#[derive(Copy, Clone, Debug)]
pub enum DigestInitError {
    /// An exclusive operation is already active on this session. 
    OperationActive,

    Mechanism(MechanismError),
    Permission(PermissionError),
    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for DigestInitError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = MechanismError::from_rv(err) {
            DigestInitError::Mechanism(err)
        }
        else if let Some(err) = PermissionError::from_rv(err) {
            DigestInitError::Permission(err)
        }
        else if let Some(err) = SessionError::from_rv(err) {
            DigestInitError::Session(err)
        }
        else {
            match err {
                sys::CKR_OPERATION_ACTIVE => DigestInitError::OperationActive,
                _ => DigestInitError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ DigestError ---------------------------------------------------

/// An error happened while performing an operation with ciphertext input.
#[derive(Clone, Copy, Debug)]
pub enum DigestError {
    /// The supplied buffer was too small.
    BufferTooSmall,

    /// A crypto operation of this type has not been previously initialized.
    OperationNotInitialized,

    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for DigestError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = SessionError::from_rv(err) {
            DigestError::Session(err)
        }
        else {
            match err {
                sys::CKR_BUFFER_TOO_SMALL => DigestError::BufferTooSmall,
                sys::CKR_OPERATION_NOT_INITIALIZED
                    => DigestError::OperationNotInitialized,
                _ => DigestError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ DigestKeyError ------------------------------------------------

/// An error happened while digesting a key.
#[derive(Copy, Clone, Debug)]
pub enum DigestKeyError {
    /// The given key cannot be digested for some reason.
    ///
    /// Perhaps the key isn’t a secret key, or perhaps the token simply can’t
    /// digest this kind of key.
    KeyIndigestible,

    /// A crypto operation of this type has not been previously initialized.
    OperationNotInitialized,

    Key(KeyError),
    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for DigestKeyError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = KeyError::from_rv(err) {
            DigestKeyError::Key(err)
        }
        else if let Some(err) = SessionError::from_rv(err) {
            DigestKeyError::Session(err)
        }
        else {
            match err {
                sys::CKR_KEY_INDIGESTIBLE => DigestKeyError::KeyIndigestible,
                sys::CKR_OPERATION_NOT_INITIALIZED
                    => DigestKeyError::OperationNotInitialized,
                _ => DigestKeyError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ VerifyError ------------------------------------------

/// An error happened while performing an operation with plaintext input.
#[derive(Clone, Copy, Debug)]
pub enum VerifyError {
    /// The plaintext input data to a cryptographic operation is invalid.
    DataInvalid,

    /// The plaintext input data to a cryptographic operation has a bad length.
    ///
    /// Depending on the operation’s mechanism, this could mean that the
    /// plaintext data is too short, too long, or is not a multiple of some
    /// particular block size.
    DataLenRange,

    /// A crypto operation of this type has not been previously initialized.
    OperationNotInitialized,

    /// The provided signature or MAC is invalid.
    SignatureInvalid,

    /// The provided signature or MAC is invalid because of a wrong length.
    SignatureLenRange,

    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for VerifyError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = SessionError::from_rv(err) {
            VerifyError::Session(err)
        }
        else {
            match err {
                sys::CKR_DATA_INVALID => VerifyError::DataInvalid,
                sys::CKR_DATA_LEN_RANGE => VerifyError::DataLenRange,
                sys::CKR_OPERATION_NOT_INITIALIZED
                    => VerifyError::OperationNotInitialized,
                sys::CKR_SIGNATURE_INVALID => VerifyError::SignatureInvalid,
                sys::CKR_SIGNATURE_LEN_RANGE
                    => VerifyError::SignatureLenRange,
                _ => VerifyError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ VerifyRecoverError -----------------------------------

/// An error happened while performing an operation with plaintext input.
#[derive(Clone, Copy, Debug)]
pub enum VerifyRecoverError {
    /// The supplied buffer was too small.
    BufferTooSmall,

    /// The plaintext input data to a cryptographic operation is invalid.
    DataInvalid,

    /// The plaintext input data to a cryptographic operation has a bad length.
    ///
    /// Depending on the operation’s mechanism, this could mean that the
    /// plaintext data is too short, too long, or is not a multiple of some
    /// particular block size.
    DataLenRange,

    /// A crypto operation of this type has not been previously initialized.
    OperationNotInitialized,

    /// The provided signature or MAC is invalid.
    SignatureInvalid,

    /// The provided signature or MAC is invalid because of a wrong length.
    SignatureLenRange,

    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for VerifyRecoverError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = SessionError::from_rv(err) {
            VerifyRecoverError::Session(err)
        }
        else {
            match err {
                sys::CKR_BUFFER_TOO_SMALL
                    => VerifyRecoverError::BufferTooSmall,
                sys::CKR_DATA_INVALID => VerifyRecoverError::DataInvalid,
                sys::CKR_DATA_LEN_RANGE => VerifyRecoverError::DataLenRange,
                sys::CKR_OPERATION_NOT_INITIALIZED
                    => VerifyRecoverError::OperationNotInitialized,
                sys::CKR_SIGNATURE_INVALID
                    => VerifyRecoverError::SignatureInvalid,
                sys::CKR_SIGNATURE_LEN_RANGE
                    => VerifyRecoverError::SignatureLenRange,
                _ => VerifyRecoverError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ CreateKeyError ---------------------------------------------

/// An error happened when creating an object.
#[derive(Copy, Clone, Debug)]
pub enum CreateKeyError {
    Template(TemplateError),
    Mechanism(MechanismError),
    Permission(PermissionError),
    Session(SessionError),
    Token(TokenError),
}

impl From<sys::CK_RV> for CreateKeyError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = TemplateError::from_rv(err) {
            CreateKeyError::Template(err)
        }
        else if let Some(err) = MechanismError::from_rv(err) {
            CreateKeyError::Mechanism(err)
        }
        else if let Some(err) = PermissionError::from_rv(err) {
            CreateKeyError::Permission(err)
        }
        else if let Some(err) = SessionError::from_rv(err) {
            CreateKeyError::Session(err)
        }
        else {
            CreateKeyError::Token(TokenError::from(err))
        }
    }
}


//------------ WrapKeyError --------------------------------------------------

/// An error happened when wrapping a key.
#[derive(Copy, Clone, Debug)]
pub enum WrapKeyError {
    /// The supplied buffer was too small.
    BufferTooSmall,

    /// While the key is allowed to be wrapped, the library just can’t.
    KeyNotWrappable,

    /// The key cannot be wrapped because it isn’t allowed to.
    ///
    /// This happens if the `CKA_EXTRACTABLE` attribute is set to `false`.
    KeyUnextractable,

    /// An operation is currently active and needs to be finished first.
    OperationActive,

    Key(KeyError),
    WrappingKey(KeyError),
    Mechanism(MechanismError),
    Permission(PermissionError),
    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for WrapKeyError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = KeyError::from_rv(err) {
            WrapKeyError::Key(err)
        }
        else if let Some(err) = KeyError::wrapping_from_rv(err) {
            WrapKeyError::WrappingKey(err)
        }
        else if let Some(err) = MechanismError::from_rv(err) {
            WrapKeyError::Mechanism(err)
        }
        else if let Some(err) = PermissionError::from_rv(err) {
            WrapKeyError::Permission(err)
        }
        else if let Some(err) = SessionError::from_rv(err) {
            WrapKeyError::Session(err)
        }
        else {
            match err {
                sys::CKR_BUFFER_TOO_SMALL => WrapKeyError::BufferTooSmall,
                sys::CKR_KEY_NOT_WRAPPABLE => WrapKeyError::KeyNotWrappable,
                sys::CKR_KEY_UNEXTRACTABLE => WrapKeyError::KeyUnextractable,
                sys::CKR_OPERATION_ACTIVE => WrapKeyError::OperationActive,
                _ => WrapKeyError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ UnwrapKeyError ------------------------------------------------

/// An error happened when wrapping a key.
#[derive(Copy, Clone, Debug)]
pub enum UnwrapKeyError {
    /// The supplied buffer was too small.
    BufferTooSmall,

    /// An operation is currently active and needs to be finished first.
    OperationActive,

    /// The wrapped key is invalid.
    WrappedKeyInvalid,

    /// The wrapped key can’t be valid because of its size.
    WrappedKeyLenRange,

    UnwrappingKey(KeyError),
    Mechanism(MechanismError),
    Template(TemplateError),
    Permission(PermissionError),
    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for UnwrapKeyError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = KeyError::unwrapping_from_rv(err) {
            UnwrapKeyError::UnwrappingKey(err)
        }
        else if let Some(err) = MechanismError::from_rv(err) {
            UnwrapKeyError::Mechanism(err)
        }
        else if let Some(err) = TemplateError::from_rv(err) {
            UnwrapKeyError::Template(err)
        }
        else if let Some(err) = PermissionError::from_rv(err) {
            UnwrapKeyError::Permission(err)
        }
        else if let Some(err) = SessionError::from_rv(err) {
            UnwrapKeyError::Session(err)
        }
        else {
            match err {
                sys::CKR_BUFFER_TOO_SMALL => UnwrapKeyError::BufferTooSmall,
                sys::CKR_OPERATION_ACTIVE => UnwrapKeyError::OperationActive,
                sys::CKR_WRAPPED_KEY_INVALID
                    => UnwrapKeyError::WrappedKeyInvalid,
                sys::CKR_WRAPPED_KEY_LEN_RANGE
                    => UnwrapKeyError::WrappedKeyLenRange,
                _ => UnwrapKeyError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ DeriveKeyError ------------------------------------------------

/// An error occurred while deriving a key.
#[derive(Copy, Clone, Debug)]
pub enum DeriveKeyError {
    /// An operation is currently active and needs to be finished first.
    OperationActive,

    Key(KeyError),
    Template(TemplateError),
    Mechanism(MechanismError),
    Permission(PermissionError),
    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for DeriveKeyError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = KeyError::from_rv(err) {
            DeriveKeyError::Key(err)
        }
        else if let Some(err) = TemplateError::from_rv(err) {
            DeriveKeyError::Template(err)
        }
        else if let Some(err) = MechanismError::from_rv(err) {
            DeriveKeyError::Mechanism(err)
        }
        else if let Some(err) = PermissionError::from_rv(err) {
            DeriveKeyError::Permission(err)
        }
        else if let Some(err) = SessionError::from_rv(err) {
            DeriveKeyError::Session(err)
        }
        else {
            match err {
                sys::CKR_OPERATION_ACTIVE => DeriveKeyError::OperationActive,
                _ => DeriveKeyError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ SeedRandomError -----------------------------------------------

/// An error happened while seeding the token’s random number generator.
#[derive(Clone, Copy, Debug)]
pub enum SeedRandomError {
    OperationActive,
    RandomSeedNotSupported,
    RandomNoRng,
    Permission(PermissionError),
    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for SeedRandomError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = PermissionError::from_rv(err) {
            SeedRandomError::Permission(err)
        }
        else if let Some(err) = SessionError::from_rv(err) {
            SeedRandomError::Session(err)
        }
        else {
            match err {
                sys::CKR_OPERATION_ACTIVE => SeedRandomError::OperationActive,
                sys::CKR_RANDOM_SEED_NOT_SUPPORTED
                    => SeedRandomError::RandomSeedNotSupported,
                sys::CKR_RANDOM_NO_RNG => SeedRandomError::RandomNoRng,
                _ => SeedRandomError::Token(TokenError::from(err))
            }
        }
    }
}


//------------ GenerateRandomError -------------------------------------------

/// An error happened while generating random data.
#[derive(Clone, Copy, Debug)]
pub enum GenerateRandomError {
    OperationActive,
    RandomNoRng,
    Permission(PermissionError),
    Session(SessionError),
    Token(TokenError)
}

impl From<sys::CK_RV> for GenerateRandomError {
    fn from(err: sys::CK_RV) -> Self {
        if let Some(err) = PermissionError::from_rv(err) {
            GenerateRandomError::Permission(err)
        }
        else if let Some(err) = SessionError::from_rv(err) {
            GenerateRandomError::Session(err)
        }
        else {
            match err {
                sys::CKR_OPERATION_ACTIVE
                    => GenerateRandomError::OperationActive,
                sys::CKR_RANDOM_NO_RNG => GenerateRandomError::RandomNoRng,
                _ => GenerateRandomError::Token(TokenError::from(err))
            }
        }
    }
}

