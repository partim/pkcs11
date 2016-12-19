
use pkcs11_sys as sys;
use super::{TokenError, to_ck_long};


//------------ Macros for Making Types ---------------------------------------

/// Creates a newtype for an enum-like type atop a `sys::CK_ULONG`.
macro_rules! ck_type {
    ( $(#[$attr:meta])*
      type $typename:ident {
          $(
              $(#[$item_attr:meta])* const $item:ident;
          )*
      }
    ) => {
        $(#[$attr])*
        #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord,
                 PartialEq, PartialOrd)]
        pub struct $typename(sys::CK_ULONG);

        impl From<sys::CK_ULONG> for $typename {
            fn from(value: sys::CK_ULONG) -> Self {
                $typename(value)
            }
        }

        impl From<$typename> for sys::CK_ULONG {
            fn from(value: $typename) -> Self {
                value.0
            }
        }
        
        $(
            $(#[$item_attr])*
            pub const $item: $typename = $typename(::pkcs11_sys::$item);
        )*
    }
}


//------------ AttributeType -------------------------------------------------

ck_type! {
    type AttributeType {
        const CKA_CLASS;
        const CKA_TOKEN              ;
        const CKA_PRIVATE            ;
        const CKA_LABEL              ;
        const CKA_APPLICATION        ;
        const CKA_VALUE;
        const CKA_OBJECT_ID          ;
        const CKA_CERTIFICATE_TYPE   ;
        const CKA_ISSUER             ;
        const CKA_SERIAL_NUMBER      ;
        const CKA_AC_ISSUER          ;
        const CKA_OWNER              ;
        const CKA_ATTR_TYPES         ;
        const CKA_TRUSTED            ;
        const CKA_CERTIFICATE_CATEGORY        ;
        const CKA_JAVA_MIDP_SECURITY_DOMAIN   ;
        const CKA_URL                         ;
        const CKA_HASH_OF_SUBJECT_PUBLIC_KEY  ;
        const CKA_HASH_OF_ISSUER_PUBLIC_KEY   ;
        const CKA_NAME_HASH_ALGORITHM         ;
        const CKA_CHECK_VALUE                 ;
        const CKA_KEY_TYPE           ;
        const CKA_SUBJECT            ;
        const CKA_ID                 ;
        const CKA_SENSITIVE          ;
        const CKA_ENCRYPT            ;
        const CKA_DECRYPT            ;
        const CKA_WRAP               ;
        const CKA_UNWRAP             ;
        const CKA_SIGN               ;
        const CKA_SIGN_RECOVER       ;
        const CKA_VERIFY             ;
        const CKA_VERIFY_RECOVER     ;
        const CKA_DERIVE             ;
        const CKA_START_DATE         ;
        const CKA_END_DATE           ;
        const CKA_MODULUS            ;
        const CKA_MODULUS_BITS       ;
        const CKA_PUBLIC_EXPONENT    ;
        const CKA_PRIVATE_EXPONENT   ;
        const CKA_PRIME_1            ;
        const CKA_PRIME_2            ;
        const CKA_EXPONENT_1         ;
        const CKA_EXPONENT_2         ;
        const CKA_COEFFICIENT        ;
        const CKA_PUBLIC_KEY_INFO    ;
        const CKA_PRIME              ;
        const CKA_SUBPRIME           ;
        const CKA_BASE               ;
        const CKA_PRIME_BITS         ;
        const CKA_SUBPRIME_BITS      ;
        const CKA_SUB_PRIME_BITS     ;
        const CKA_VALUE_BITS         ;
        const CKA_VALUE_LEN          ;
        const CKA_EXTRACTABLE        ;
        const CKA_LOCAL              ;
        const CKA_NEVER_EXTRACTABLE  ;
        const CKA_ALWAYS_SENSITIVE   ;
        const CKA_KEY_GEN_MECHANISM  ;
        const CKA_MODIFIABLE         ;
        const CKA_COPYABLE           ;
        const CKA_DESTROYABLE        ;
        const CKA_ECDSA_PARAMS       ;
        const CKA_EC_PARAMS          ;
        const CKA_EC_POINT           ;
        const CKA_SECONDARY_AUTH     ;
        const CKA_AUTH_PIN_FLAGS     ;
        const CKA_ALWAYS_AUTHENTICATE  ;
        const CKA_WRAP_WITH_TRUSTED    ;
        const CKA_WRAP_TEMPLATE        ;
        const CKA_UNWRAP_TEMPLATE      ;
        const CKA_DERIVE_TEMPLATE      ;
        const CKA_OTP_FORMAT                ;
        const CKA_OTP_LENGTH                ;
        const CKA_OTP_TIME_INTERVAL         ;
        const CKA_OTP_USER_FRIENDLY_MODE    ;
        const CKA_OTP_CHALLENGE_REQUIREMENT ;
        const CKA_OTP_TIME_REQUIREMENT      ;
        const CKA_OTP_COUNTER_REQUIREMENT   ;
        const CKA_OTP_PIN_REQUIREMENT       ;
        const CKA_OTP_COUNTER               ;
        const CKA_OTP_TIME                  ;
        const CKA_OTP_USER_IDENTIFIER       ;
        const CKA_OTP_SERVICE_IDENTIFIER    ;
        const CKA_OTP_SERVICE_LOGO          ;
        const CKA_OTP_SERVICE_LOGO_TYPE     ;
        const CKA_GOSTR3410_PARAMS            ;
        const CKA_GOSTR3411_PARAMS            ;
        const CKA_GOST28147_PARAMS            ;
        const CKA_HW_FEATURE_TYPE;
        const CKA_RESET_ON_INIT               ;
        const CKA_HAS_RESET                   ;
        const CKA_PIXEL_X                     ;
        const CKA_PIXEL_Y                     ;
        const CKA_RESOLUTION                  ;
        const CKA_CHAR_ROWS                   ;
        const CKA_CHAR_COLUMNS                ;
        const CKA_COLOR                       ;
        const CKA_BITS_PER_PIXEL              ;
        const CKA_CHAR_SETS                   ;
        const CKA_ENCODING_METHODS            ;
        const CKA_MIME_TYPES                  ;
        const CKA_MECHANISM_TYPE              ;
        const CKA_REQUIRED_CMS_ATTRIBUTES     ;
        const CKA_DEFAULT_CMS_ATTRIBUTES      ;
        const CKA_SUPPORTED_CMS_ATTRIBUTES    ;
        const CKA_ALLOWED_MECHANISMS          ;
        const CKA_VENDOR_DEFINED              ;
    }
}


//------------ KeyType -------------------------------------------------------

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct KeyType(sys::CK_KEY_TYPE);

impl KeyType {
    pub fn aes() -> Self { KeyType(sys::CKK_AES) }
}


//------------ HwFeatureType -------------------------------------------------

ck_type! {
    type HwFeatureType {
        /// A hardware counter that exists on the device.
        const CKH_MONOTONIC_COUNTER;

        /// A real-time clock that exists on the device.
        const CKH_CLOCK;

        /// The presentation capabilities of a device.
        const CKH_USER_INTERFACE;

        /// Vendor-defined hardware values of a device.
        const CKH_VENDOR_DEFINED;
    }
}


//------------ MechanismType -------------------------------------------------

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct MechanismType(sys::CK_MECHANISM_TYPE);

impl MechanismType {
    pub fn aes_key_gen() -> Self { MechanismType(sys::CKM_AES_KEY_GEN) }
    pub fn aes_cbc_pad() -> Self { MechanismType(sys::CKM_AES_CBC_PAD) }
}

impl From<sys::CK_MECHANISM_TYPE> for MechanismType {
    fn from(value: sys::CK_MECHANISM_TYPE) -> Self {
        MechanismType(value)
    }
}

impl From<MechanismType> for sys::CK_MECHANISM_TYPE {
    fn from(value: MechanismType) -> Self {
        value.0
    }
}


//------------ ObjectClass ---------------------------------------------------

ck_type! {
    type ObjectClass {
        const CKO_SECRET_KEY;
    }
}


//------------ ObjectHandle --------------------------------------------------

#[derive(Copy, Clone, Debug, Default)]
pub struct ObjectHandle(sys::CK_OBJECT_HANDLE);

impl From<sys::CK_OBJECT_HANDLE> for ObjectHandle {
    fn from(handle: sys::CK_OBJECT_HANDLE) -> Self {
        ObjectHandle(handle)
    }
}

impl From<ObjectHandle> for sys::CK_OBJECT_HANDLE {
    fn from(handle: ObjectHandle) -> Self {
        handle.0
    }
}


//------------ SessionHandle -------------------------------------------------

#[derive(Copy, Clone, Debug)]
pub struct SessionHandle(sys::CK_SESSION_HANDLE);

impl From<sys::CK_SESSION_HANDLE> for SessionHandle {
    fn from(handle: sys::CK_SESSION_HANDLE) -> Self {
        SessionHandle(handle)
    }
}

impl From<SessionHandle> for sys::CK_SESSION_HANDLE {
    fn from(handle: SessionHandle) -> Self {
        handle.0
    }
}


//------------ Size ----------------------------------------------------------

#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Size(sys::CK_ULONG);

impl From<usize> for Size {
    fn from(size: usize) -> Self {
        Size(to_ck_long(size))
    }
}


//------------ SlotId --------------------------------------------------------

#[derive(Copy, Clone, Debug)]
pub struct SlotId(sys::CK_SLOT_ID);

impl From<sys::CK_SLOT_ID> for SlotId {
    fn from(id: sys::CK_SLOT_ID) -> Self {
        SlotId(id)
    }
}

impl From<SlotId> for sys::CK_SLOT_ID {
    fn from(id: SlotId) -> Self {
        id.0
    }
}


//------------ State ---------------------------------------------------------

/// The session state.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum State {
    RoPublicSession,
    RoUserFunctions,
    RwPublicSession,
    RwUserFunctions,
    RwSoFunctions,
}

impl State {
    pub fn try_from(state: sys::CK_STATE) -> Result<Self, TokenError> {
        match state {
            sys::CKS_RO_PUBLIC_SESSION => Ok(State::RoPublicSession),
            sys::CKS_RO_USER_FUNCTIONS => Ok(State::RoUserFunctions),
            sys::CKS_RW_PUBLIC_SESSION => Ok(State::RwPublicSession),
            sys::CKS_RW_USER_FUNCTIONS => Ok(State::RwUserFunctions),
            sys::CKS_RW_SO_FUNCTIONS => Ok(State::RwSoFunctions),
            _ => Err(TokenError::GeneralError),
        }
    }
}


//------------ UserType ------------------------------------------------------

/// The types of users for trying to log into a token.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UserType {
    /// The security officer.
    So,

    /// A normal user.
    User,

    /// Context specific user.
    ContextSpecific,
}

impl From<UserType> for sys::CK_USER_TYPE {
    fn from(value: UserType) -> Self {
        match value {
            UserType::So => sys::CKU_SO,
            UserType::User => sys::CKU_USER,
            UserType::ContextSpecific => sys::CKU_CONTEXT_SPECIFIC,
        }
    }
}


