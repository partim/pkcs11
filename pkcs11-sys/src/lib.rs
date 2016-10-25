//! The System Interface to PKCS #11 aka Cryptoki.
//!
//! For the specification, see:
//! http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html
//! and
//! http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/pkcs11-curr-v2.40.html
#![allow(non_camel_case_types, non_snake_case)]

extern crate libc;


//------------ pkcs11t.h -----------------------------------------------------

pub const CRYPTOKI_VERSION_MAJOR: CK_BYTE = 2;
pub const CRYPTOKI_VERSION_MINOR: CK_BYTE = 40;
pub const CRYPTOKI_VERSION_AMENDMENT: CK_BYTE = 0;

pub const CK_TRUE: CK_BBOOL = 1;
pub const CK_FALSE: CK_BBOOL = 0;

/// An unsigned 8-bit value.
pub type CK_BYTE = libc::c_uchar;

/// An unsigned 8-bit character.
pub type CK_CHAR = CK_BYTE;

/// An 8-bit UTF-8 character.
pub type CK_UTF8CHAR = CK_BYTE;

/// A BYTE-sized Boolean flag.
pub type CK_BBOOL = CK_BYTE;

/// An unsigned value, at least 32 bits long.
pub type CK_ULONG = libc::c_ulong;

/// A signed value, the same size as a `CK_ULONG`.
pub type CK_LONG = libc::c_long;

/// At least 32 bits; each bit is a Boolean flag.
pub type CK_FLAGS = CK_ULONG;

pub const CK_UNAVAILABLE_INFORMATION: CK_ULONG = !0;
pub const CK_EFFECTIVELY_INFINITE: CK_ULONG = 0;

pub type CK_VOID = libc::c_void;

/// A value always invalid if used as a session handle or object handle.
pub const CK_INVALID_HANDLE: CK_ULONG = 0;

#[repr(C)]
pub struct CK_VERSION {
    /// Integer portion of version number.
    pub major: CK_BYTE,

    /// 1/100ths portion of the version number.
    pub minor: CK_BYTE
}

#[repr(C)]
pub struct CK_INFO {
    /// Cryptoki interface ver.
    pub cryptokiVersion: CK_VERSION,

    /// Blank padded.
    pub manufacturerID: [CK_UTF8CHAR; 32],

    /// Must be zero.
    pub flags: CK_FLAGS,

    /// blank padded.
    pub libraryDescription: [CK_UTF8CHAR; 32],

    /// version of library
    pub libraryVersion: CK_VERSION,
}

/// Enumerates type tyes of notifications that Cryptoki provides to an
/// application.
pub type CK_NOTIFICATION = CK_ULONG;

pub const CKN_SURRENDER: CK_NOTIFICATION = 0;
pub const CKN_OTP_CHANGED: CK_NOTIFICATION = 1;

pub type CK_SLOT_ID = CK_ULONG;

/// Provides information about a slot.
#[repr(C)]
pub struct CK_SLOT_INFO {
    /// Blank padded.
    pub slotDescription: [CK_UTF8CHAR; 64],

    /// Blank padded.
    pub manufacturerID: [CK_UTF8CHAR; 32],

    pub flags: CK_FLAGS,

    pub hardwareVersion: CK_VERSION,
    pub firmwareVersion: CK_VERSION
}

// Flags for CK_SLOT_INFO.flags

/// A token is there.
pub const CKF_TOKEN_PRESENT: CK_FLAGS = 1;

/// Removable devices.
pub const CKF_REMOVABLE_DEVICE: CK_FLAGS = 2;

/// Hardware slot.
pub const CKF_HW_SLOW: CK_FLAGS = 4;

/// Provides information about a token.
#[repr(C)]
pub struct CK_TOKEN_INFO {
    /// Blank padded.
    pub label: [CK_UTF8CHAR; 32],

    /// Blank padded.
    pub manufacturer: [CK_UTF8CHAR; 32],

    /// Blank padded.
    pub model: [CK_UTF8CHAR; 16],

    /// See below.
    pub flags: CK_FLAGS,


    /// Max open sessions.
    pub ulMaxSessionCount: CK_ULONG,
    
    /// Sessions now open.
    pub ulSessionCount: CK_ULONG,
    
    /// Max R/W sessions.
    pub ulMaxRwSessionCount: CK_ULONG,
    
    /// In bytes.
    pub ulRwSessionCount: CK_ULONG,
    
    /// In bytes.
    pub ulMaxPinLen: CK_ULONG,
    
    /// In bytes.
    pub ulMinPinLen: CK_ULONG,
    
    /// In bytes.
    pub ulTotalPublicMemory: CK_ULONG,
    
    /// In bytes.
    pub ulFreePublicMemory: CK_ULONG,
    
    /// In bytes.
    pub ulTotalPrivateMemory: CK_ULONG,
    
    /// In bytes.
    pub ulFreePrivateMemory: CK_ULONG,

    /// Hardware version.
    pub hardwareVersion: CK_VERSION,

    /// Firmware version.
    pub firmwareVersion: CK_VERSION,

    /// Time.
    pub utcTime: [CK_CHAR; 16]
}

// Flags for CK_SLOT_INFO.flags
/// Has random number generator.
pub const CKF_RNG: CK_FLAGS = 1;

/// Token is write-protected.
pub const CKF_WRITE_PROTECTED: CK_FLAGS = 2;

/// User must log in.
pub const CKF_LOGIN_REQUIRED: CK_FLAGS = 4;

/// Normal user’s PIN is set.
pub const CKF_USER_PIN_INITIALIZED: CK_FLAGS = 8;

/// Restore key not needed.
///
/// If it is set, that means that *every* time the state of cryptographic
/// operations of a session us successfully saved, all keys needed to
/// continue thos operations are stored in the state.
pub const CKF_RESTORE_KEY_NOT_NEEDED: CK_FLAGS = 0x20;

/// Clock on token.
///
/// If it is set, that means that the token has some sort of clock. The
/// time on that clock is returned in the token info structure.
pub const CKF_CLOCK_ON_TOKEN: CK_FLAGS = 0x40;

/// Protected authentication path.
///
/// If it is set, that means that there is some way for the user to login
/// without sending a PIN through the Cryptoki library itself.
pub const CKF_PROTECTED_AUTHENTICATION_PATH: CK_FLAGS = 0x100;

/// Dual crypto operations.
///
/// If it is true, that means that a single session with the token can
/// perform dual simultaneous cryptographic operations (digest and encrypt;
/// decrypt and digest; sign and encrypt; and decrypt and sign).
pub const CKF_DUAL_CRYPTO_OPERATIONS: CK_FLAGS = 0x200;

/// Token initialized.
///
/// If it is true, the token has been initialized using `C_InitializeToken`
/// or an equivalent mechanism outside the scope of PKCS #11. Calling
/// `C_InitializeToken` when this flag is set will cause the token to be
/// reinitialized.
pub const CKF_TOKEN_INITIALIZED: CK_FLAGS = 0x400;

/// Secondary authentication.
///
/// If it is true, the token supports secondary authentication for private
/// key objects.
pub const CKF_SECONDARY_AUTHENTICATION: CK_FLAGS = 0x800;

/// User PIN count low.
///
/// If it is true, an incorrect user login PIN has been entered at least once
/// since the last successful authentication.
pub const CKF_USER_PIN_COUNT_LOW: CK_FLAGS = 0x10000; // sic!

/// User PIN final try.
///
/// If it is true, supplying an incorrect user PIN will it to become locked.
pub const CKF_USER_PIN_FINAL_TRY: CK_FLAGS = 0x20000;

/// User PIN locked.
///
/// If it is true, the user PIN has been locked. User login to the token is
/// not possible.
pub const CKF_USER_PIN_LOCKED: CK_FLAGS = 0x40000;

/// User PIN to be changed.
///
/// If it is true, the user PIN value is the default value set by token
/// initialization or manufacturing, or the PIN has been expired by the card.
pub const CKF_USER_PIN_TO_BE_CHANGED: CK_FLAGS = 0x80000;

/// SO PIN count low.
///
/// If it is true, an incorrect SO login PIN has been entered at least once
/// since the last successful authentication.
pub const CKF_SO_PIN_COUNT_LOW: CK_FLAGS = 0x100000;

/// SO PIN final try.
///
/// If it is true, supplying an incorrect SO PIN will it to become locked.
pub const CKF_SO_PIN_FINAL_TRY: CK_FLAGS = 0x200000;

/// SO PIN locked.
///
/// If it is true, the SO PIN has been locked. SO login to the token is not
/// possible.
pub const CKF_SO_PIN_LOCKED: CK_FLAGS = 0x400000;

/// SO PIN to be changed.
///
/// If it is true, the SO PIN value is the default value set by token
/// initialization or manufacturing, or the PIN has been expired by the card.
pub const CKF_SO_PIN_TO_BE_CHANGED: CK_FLAGS = 0x800000;

pub const CKF_ERROR_STATE: CK_FLAGS = 0x1000000;

/// A Cryptoki-assigned value that identifies a session.
pub type CK_SESSION_HANDLE = CK_ULONG;

/// Enumerates the types of Cryptoki users.
pub type CK_USER_TYPE = CK_ULONG;

/// Security officer.
pub const CKU_SO: CK_USER_TYPE = 0;

/// Normal user.
pub const CKU_USER: CK_USER_TYPE = 1;

/// Context specific.
pub const CKU_CONTEXT_SPECIFIC: CK_USER_TYPE = 2;

/// Enumerates the session states.
pub type CK_STATE = CK_ULONG;

pub const CKS_RO_PUBLIC_SESSION: CK_STATE = 0;
pub const CKS_RO_USER_FUNCTIONS: CK_STATE = 1;
pub const CKS_RW_PUBLIC_SESSION: CK_STATE = 2;
pub const CKS_RW_USER_FUNCTIONS: CK_STATE = 3;
pub const CKS_RW_SO_FUNCTIONS: CK_STATE = 4;

/// Provides information about a session.
#[repr(C)]
pub struct CK_SESSION_INFO {
    pub slotID: CK_SLOT_ID,
    pub state: CK_STATE,
    pub flags: CK_FLAGS,
    pub ulDeviceError: CK_ULONG,
}

/// Session is r/w.
pub const CFK_RW_SESSION: CK_FLAGS = 2;

/// No parallel.
pub const CFK_SERIAL_SESSION: CK_FLAGS = 4;

/// A token-specific identifier for an object.
pub type CK_OBJECT_HANDLE = CK_ULONG;

/// Identifies the classes (or types) of objects that Cryptoki recognizes.
pub type CK_OBJECT_CLASS = CK_ULONG;

pub const CKO_DATA: CK_OBJECT_CLASS = 0;
pub const CKO_CERTIFICATE: CK_OBJECT_CLASS = 1;
pub const CKO_PUBLIC_KEY: CK_OBJECT_CLASS = 2;
pub const CKO_PRIVATE_KEY: CK_OBJECT_CLASS = 3;
pub const CKO_SECRET_KEY: CK_OBJECT_CLASS = 4;
pub const CKO_HW_FEATURE: CK_OBJECT_CLASS = 5;
pub const CKO_DOMAIN_PARAMETERS: CK_OBJECT_CLASS = 6;
pub const CKO_MECHANISM: CK_OBJECT_CLASS = 7;
pub const CKO_OTP_KEY: CK_OBJECT_CLASS = 8;

pub const CKO_VENDOR_DEFINED: CK_OBJECT_CLASS = 0x8000_0000;

/// Identifies the hardware feature type of an object of `CKO_HW_FEATURE` class.
pub type CK_HW_FEATURE_TYPE = CK_ULONG;

pub const CKH_MONOTONIC_COUNTER  : CK_HW_FEATURE_TYPE = 0x00000001;
pub const CKH_CLOCK              : CK_HW_FEATURE_TYPE = 0x00000002;
pub const CKH_USER_INTERFACE     : CK_HW_FEATURE_TYPE = 0x00000003;
pub const CKH_VENDOR_DEFINED     : CK_HW_FEATURE_TYPE = 0x80000000;

/// Identifies a key type.
pub type CK_KEY_TYPE = CK_ULONG;

pub const CKK_RSA                 : CK_KEY_TYPE = 0x00000000;
pub const CKK_DSA                 : CK_KEY_TYPE = 0x00000001;
pub const CKK_DH                  : CK_KEY_TYPE = 0x00000002;
pub const CKK_ECDSA               : CK_KEY_TYPE = 0x00000003; /* Deprecated */
pub const CKK_EC                  : CK_KEY_TYPE = 0x00000003;
pub const CKK_X9_42_DH            : CK_KEY_TYPE = 0x00000004;
pub const CKK_KEA                 : CK_KEY_TYPE = 0x00000005;
pub const CKK_GENERIC_SECRET      : CK_KEY_TYPE = 0x00000010;
pub const CKK_RC2                 : CK_KEY_TYPE = 0x00000011;
pub const CKK_RC4                 : CK_KEY_TYPE = 0x00000012;
pub const CKK_DES                 : CK_KEY_TYPE = 0x00000013;
pub const CKK_DES2                : CK_KEY_TYPE = 0x00000014;
pub const CKK_DES3                : CK_KEY_TYPE = 0x00000015;
pub const CKK_CAST                : CK_KEY_TYPE = 0x00000016;
pub const CKK_CAST3               : CK_KEY_TYPE = 0x00000017;
pub const CKK_CAST5               : CK_KEY_TYPE = 0x00000018; /* Deprecated */
pub const CKK_CAST128             : CK_KEY_TYPE = 0x00000018;
pub const CKK_RC5                 : CK_KEY_TYPE = 0x00000019;
pub const CKK_IDEA                : CK_KEY_TYPE = 0x0000001A;
pub const CKK_SKIPJACK            : CK_KEY_TYPE = 0x0000001B;
pub const CKK_BATON               : CK_KEY_TYPE = 0x0000001C;
pub const CKK_JUNIPER             : CK_KEY_TYPE = 0x0000001D;
pub const CKK_CDMF                : CK_KEY_TYPE = 0x0000001E;
pub const CKK_AES                 : CK_KEY_TYPE = 0x0000001F;
pub const CKK_BLOWFISH            : CK_KEY_TYPE = 0x00000020;
pub const CKK_TWOFISH             : CK_KEY_TYPE = 0x00000021;
pub const CKK_SECURID             : CK_KEY_TYPE = 0x00000022;
pub const CKK_HOTP                : CK_KEY_TYPE = 0x00000023;
pub const CKK_ACTI                : CK_KEY_TYPE = 0x00000024;
pub const CKK_CAMELLIA            : CK_KEY_TYPE = 0x00000025;
pub const CKK_ARIA                : CK_KEY_TYPE = 0x00000026;

pub const CKK_MD5_HMAC            : CK_KEY_TYPE = 0x00000027;
pub const CKK_SHA_1_HMAC          : CK_KEY_TYPE = 0x00000028;
pub const CKK_RIPEMD128_HMAC      : CK_KEY_TYPE = 0x00000029;
pub const CKK_RIPEMD160_HMAC      : CK_KEY_TYPE = 0x0000002A;
pub const CKK_SHA256_HMAC         : CK_KEY_TYPE = 0x0000002B;
pub const CKK_SHA384_HMAC         : CK_KEY_TYPE = 0x0000002C;
pub const CKK_SHA512_HMAC         : CK_KEY_TYPE = 0x0000002D;
pub const CKK_SHA224_HMAC         : CK_KEY_TYPE = 0x0000002E;

pub const CKK_SEED                : CK_KEY_TYPE = 0x0000002F;
pub const CKK_GOSTR3410           : CK_KEY_TYPE = 0x00000030;
pub const CKK_GOSTR3411           : CK_KEY_TYPE = 0x00000031;
pub const CKK_GOST28147           : CK_KEY_TYPE = 0x00000032;

pub const CKK_VENDOR_DEFINED      : CK_KEY_TYPE = 0x80000000;

/// Identifies a certificate type.
pub type CK_CERTIFICATE_TYPE = CK_ULONG;

pub const CK_CERTIFICATE_CATEGORY_UNSPECIFIED : CK_ULONG = 0;
pub const CK_CERTIFICATE_CATEGORY_TOKEN_USER  : CK_ULONG = 1;
pub const CK_CERTIFICATE_CATEGORY_AUTHORITY   : CK_ULONG = 2;
pub const CK_CERTIFICATE_CATEGORY_OTHER_ENTITY: CK_ULONG = 3;

pub const CK_SECURITY_DOMAIN_UNSPECIFIED : CK_ULONG = 0;
pub const CK_SECURITY_DOMAIN_MANUFACTURER: CK_ULONG = 1;
pub const CK_SECURITY_DOMAIN_OPERATOR    : CK_ULONG = 2;
pub const CK_SECURITY_DOMAIN_THIRD_PARTY : CK_ULONG = 3;

pub const CKC_X_509               : CK_CERTIFICATE_TYPE = 0x00000000;
pub const CKC_X_509_ATTR_CERT     : CK_CERTIFICATE_TYPE = 0x00000001;
pub const CKC_WTLS                : CK_CERTIFICATE_TYPE = 0x00000002;
pub const CKC_VENDOR_DEFINED      : CK_CERTIFICATE_TYPE = 0x80000000;

/// Identifies an attribute type.
pub type CK_ATTRIBUTE_TYPE = CK_ULONG;

/// Identifies an attribute which consists of an array of values.
pub const CKF_ARRAY_ATTRIBUTE: CK_ATTRIBUTE_TYPE = 0x40000000;

// Related to the CKA_OTP_FORMAT attribute
pub const CK_OTP_FORMAT_DECIMAL     : CK_ULONG = 0;
pub const CK_OTP_FORMAT_HEXADECIMAL : CK_ULONG = 1;
pub const CK_OTP_FORMAT_ALPHANUMERIC: CK_ULONG = 2;
pub const CK_OTP_FORMAT_BINARY      : CK_ULONG = 3;

// Related to the CKA_OTP_..._REQUIREMENT attributes
pub const CK_OTP_PARAM_IGNORED  : CK_ULONG = 0;
pub const CK_OTP_PARAM_OPTIONAL : CK_ULONG = 1;
pub const CK_OTP_PARAM_MANDATORY: CK_ULONG = 2;

pub const CKA_CLASS              : CK_ATTRIBUTE_TYPE = 0x00000000;
pub const CKA_TOKEN              : CK_ATTRIBUTE_TYPE = 0x00000001;
pub const CKA_PRIVATE            : CK_ATTRIBUTE_TYPE = 0x00000002;
pub const CKA_LABEL              : CK_ATTRIBUTE_TYPE = 0x00000003;
pub const CKA_APPLICATION        : CK_ATTRIBUTE_TYPE = 0x00000010;
pub const CKA_VALUE              : CK_ATTRIBUTE_TYPE = 0x00000011;
pub const CKA_OBJECT_ID          : CK_ATTRIBUTE_TYPE = 0x00000012;
pub const CKA_CERTIFICATE_TYPE   : CK_ATTRIBUTE_TYPE = 0x00000080;
pub const CKA_ISSUER             : CK_ATTRIBUTE_TYPE = 0x00000081;
pub const CKA_SERIAL_NUMBER      : CK_ATTRIBUTE_TYPE = 0x00000082;
pub const CKA_AC_ISSUER          : CK_ATTRIBUTE_TYPE = 0x00000083;
pub const CKA_OWNER              : CK_ATTRIBUTE_TYPE = 0x00000084;
pub const CKA_ATTR_TYPES         : CK_ATTRIBUTE_TYPE = 0x00000085;
pub const CKA_TRUSTED            : CK_ATTRIBUTE_TYPE = 0x00000086;
pub const CKA_CERTIFICATE_CATEGORY        : CK_ATTRIBUTE_TYPE = 0x00000087;
pub const CKA_JAVA_MIDP_SECURITY_DOMAIN   : CK_ATTRIBUTE_TYPE = 0x00000088;
pub const CKA_URL                         : CK_ATTRIBUTE_TYPE = 0x00000089;
pub const CKA_HASH_OF_SUBJECT_PUBLIC_KEY  : CK_ATTRIBUTE_TYPE = 0x0000008A;
pub const CKA_HASH_OF_ISSUER_PUBLIC_KEY   : CK_ATTRIBUTE_TYPE = 0x0000008B;
pub const CKA_NAME_HASH_ALGORITHM         : CK_ATTRIBUTE_TYPE = 0x0000008C;
pub const CKA_CHECK_VALUE                 : CK_ATTRIBUTE_TYPE = 0x00000090;

pub const CKA_KEY_TYPE           : CK_ATTRIBUTE_TYPE = 0x00000100;
pub const CKA_SUBJECT            : CK_ATTRIBUTE_TYPE = 0x00000101;
pub const CKA_ID                 : CK_ATTRIBUTE_TYPE = 0x00000102;
pub const CKA_SENSITIVE          : CK_ATTRIBUTE_TYPE = 0x00000103;
pub const CKA_ENCRYPT            : CK_ATTRIBUTE_TYPE = 0x00000104;
pub const CKA_DECRYPT            : CK_ATTRIBUTE_TYPE = 0x00000105;
pub const CKA_WRAP               : CK_ATTRIBUTE_TYPE = 0x00000106;
pub const CKA_UNWRAP             : CK_ATTRIBUTE_TYPE = 0x00000107;
pub const CKA_SIGN               : CK_ATTRIBUTE_TYPE = 0x00000108;
pub const CKA_SIGN_RECOVER       : CK_ATTRIBUTE_TYPE = 0x00000109;
pub const CKA_VERIFY             : CK_ATTRIBUTE_TYPE = 0x0000010A;
pub const CKA_VERIFY_RECOVER     : CK_ATTRIBUTE_TYPE = 0x0000010B;
pub const CKA_DERIVE             : CK_ATTRIBUTE_TYPE = 0x0000010C;
pub const CKA_START_DATE         : CK_ATTRIBUTE_TYPE = 0x00000110;
pub const CKA_END_DATE           : CK_ATTRIBUTE_TYPE = 0x00000111;
pub const CKA_MODULUS            : CK_ATTRIBUTE_TYPE = 0x00000120;
pub const CKA_MODULUS_BITS       : CK_ATTRIBUTE_TYPE = 0x00000121;
pub const CKA_PUBLIC_EXPONENT    : CK_ATTRIBUTE_TYPE = 0x00000122;
pub const CKA_PRIVATE_EXPONENT   : CK_ATTRIBUTE_TYPE = 0x00000123;
pub const CKA_PRIME_1            : CK_ATTRIBUTE_TYPE = 0x00000124;
pub const CKA_PRIME_2            : CK_ATTRIBUTE_TYPE = 0x00000125;
pub const CKA_EXPONENT_1         : CK_ATTRIBUTE_TYPE = 0x00000126;
pub const CKA_EXPONENT_2         : CK_ATTRIBUTE_TYPE = 0x00000127;
pub const CKA_COEFFICIENT        : CK_ATTRIBUTE_TYPE = 0x00000128;
pub const CKA_PUBLIC_KEY_INFO    : CK_ATTRIBUTE_TYPE = 0x00000129;
pub const CKA_PRIME              : CK_ATTRIBUTE_TYPE = 0x00000130;
pub const CKA_SUBPRIME           : CK_ATTRIBUTE_TYPE = 0x00000131;
pub const CKA_BASE               : CK_ATTRIBUTE_TYPE = 0x00000132;

pub const CKA_PRIME_BITS         : CK_ATTRIBUTE_TYPE = 0x00000133;
pub const CKA_SUBPRIME_BITS      : CK_ATTRIBUTE_TYPE = 0x00000134;
pub const CKA_SUB_PRIME_BITS     : CK_ATTRIBUTE_TYPE = CKA_SUBPRIME_BITS;

pub const CKA_VALUE_BITS         : CK_ATTRIBUTE_TYPE = 0x00000160;
pub const CKA_VALUE_LEN          : CK_ATTRIBUTE_TYPE = 0x00000161;
pub const CKA_EXTRACTABLE        : CK_ATTRIBUTE_TYPE = 0x00000162;
pub const CKA_LOCAL              : CK_ATTRIBUTE_TYPE = 0x00000163;
pub const CKA_NEVER_EXTRACTABLE  : CK_ATTRIBUTE_TYPE = 0x00000164;
pub const CKA_ALWAYS_SENSITIVE   : CK_ATTRIBUTE_TYPE = 0x00000165;
pub const CKA_KEY_GEN_MECHANISM  : CK_ATTRIBUTE_TYPE = 0x00000166;

pub const CKA_MODIFIABLE         : CK_ATTRIBUTE_TYPE = 0x00000170;
pub const CKA_COPYABLE           : CK_ATTRIBUTE_TYPE = 0x00000171;

pub const CKA_DESTROYABLE        : CK_ATTRIBUTE_TYPE = 0x00000172;

pub const CKA_ECDSA_PARAMS       : CK_ATTRIBUTE_TYPE = 0x00000180; /* Deprecated */
pub const CKA_EC_PARAMS          : CK_ATTRIBUTE_TYPE = 0x00000180;

pub const CKA_EC_POINT           : CK_ATTRIBUTE_TYPE = 0x00000181;

pub const CKA_SECONDARY_AUTH     : CK_ATTRIBUTE_TYPE = 0x00000200; /* Deprecated */
pub const CKA_AUTH_PIN_FLAGS     : CK_ATTRIBUTE_TYPE = 0x00000201; /* Deprecated */

pub const CKA_ALWAYS_AUTHENTICATE  : CK_ATTRIBUTE_TYPE = 0x00000202;

pub const CKA_WRAP_WITH_TRUSTED    : CK_ATTRIBUTE_TYPE = 0x00000210;
pub const CKA_WRAP_TEMPLATE        : CK_ATTRIBUTE_TYPE =
                                        CKF_ARRAY_ATTRIBUTE | 0x00000211;
pub const CKA_UNWRAP_TEMPLATE      : CK_ATTRIBUTE_TYPE =
                                        CKF_ARRAY_ATTRIBUTE | 0x00000212;
pub const CKA_DERIVE_TEMPLATE      : CK_ATTRIBUTE_TYPE =
                                        CKF_ARRAY_ATTRIBUTE | 0x00000213;

pub const CKA_OTP_FORMAT                : CK_ATTRIBUTE_TYPE = 0x00000220;
pub const CKA_OTP_LENGTH                : CK_ATTRIBUTE_TYPE = 0x00000221;
pub const CKA_OTP_TIME_INTERVAL         : CK_ATTRIBUTE_TYPE = 0x00000222;
pub const CKA_OTP_USER_FRIENDLY_MODE    : CK_ATTRIBUTE_TYPE = 0x00000223;
pub const CKA_OTP_CHALLENGE_REQUIREMENT : CK_ATTRIBUTE_TYPE = 0x00000224;
pub const CKA_OTP_TIME_REQUIREMENT      : CK_ATTRIBUTE_TYPE = 0x00000225;
pub const CKA_OTP_COUNTER_REQUIREMENT   : CK_ATTRIBUTE_TYPE = 0x00000226;
pub const CKA_OTP_PIN_REQUIREMENT       : CK_ATTRIBUTE_TYPE = 0x00000227;
pub const CKA_OTP_COUNTER               : CK_ATTRIBUTE_TYPE = 0x0000022E;
pub const CKA_OTP_TIME                  : CK_ATTRIBUTE_TYPE = 0x0000022F;
pub const CKA_OTP_USER_IDENTIFIER       : CK_ATTRIBUTE_TYPE = 0x0000022A;
pub const CKA_OTP_SERVICE_IDENTIFIER    : CK_ATTRIBUTE_TYPE = 0x0000022B;
pub const CKA_OTP_SERVICE_LOGO          : CK_ATTRIBUTE_TYPE = 0x0000022C;
pub const CKA_OTP_SERVICE_LOGO_TYPE     : CK_ATTRIBUTE_TYPE = 0x0000022D;

pub const CKA_GOSTR3410_PARAMS            : CK_ATTRIBUTE_TYPE = 0x00000250;
pub const CKA_GOSTR3411_PARAMS            : CK_ATTRIBUTE_TYPE = 0x00000251;
pub const CKA_GOST28147_PARAMS            : CK_ATTRIBUTE_TYPE = 0x00000252;

pub const CKA_HW_FEATURE_TYPE             : CK_ATTRIBUTE_TYPE = 0x00000300;
pub const CKA_RESET_ON_INIT               : CK_ATTRIBUTE_TYPE = 0x00000301;
pub const CKA_HAS_RESET                   : CK_ATTRIBUTE_TYPE = 0x00000302;

pub const CKA_PIXEL_X                     : CK_ATTRIBUTE_TYPE = 0x00000400;
pub const CKA_PIXEL_Y                     : CK_ATTRIBUTE_TYPE = 0x00000401;
pub const CKA_RESOLUTION                  : CK_ATTRIBUTE_TYPE = 0x00000402;
pub const CKA_CHAR_ROWS                   : CK_ATTRIBUTE_TYPE = 0x00000403;
pub const CKA_CHAR_COLUMNS                : CK_ATTRIBUTE_TYPE = 0x00000404;
pub const CKA_COLOR                       : CK_ATTRIBUTE_TYPE = 0x00000405;
pub const CKA_BITS_PER_PIXEL              : CK_ATTRIBUTE_TYPE = 0x00000406;
pub const CKA_CHAR_SETS                   : CK_ATTRIBUTE_TYPE = 0x00000480;
pub const CKA_ENCODING_METHODS            : CK_ATTRIBUTE_TYPE = 0x00000481;
pub const CKA_MIME_TYPES                  : CK_ATTRIBUTE_TYPE = 0x00000482;
pub const CKA_MECHANISM_TYPE              : CK_ATTRIBUTE_TYPE = 0x00000500;
pub const CKA_REQUIRED_CMS_ATTRIBUTES     : CK_ATTRIBUTE_TYPE = 0x00000501;
pub const CKA_DEFAULT_CMS_ATTRIBUTES      : CK_ATTRIBUTE_TYPE = 0x00000502;
pub const CKA_SUPPORTED_CMS_ATTRIBUTES    : CK_ATTRIBUTE_TYPE = 0x00000503;
pub const CKA_ALLOWED_MECHANISMS          : CK_ATTRIBUTE_TYPE =
                                            CKF_ARRAY_ATTRIBUTE | 0x00000600;

pub const CKA_VENDOR_DEFINED              : CK_ATTRIBUTE_TYPE = 0x80000000;

/// Includes the type, length, and value of an attribute.
#[repr(C)]
pub struct CK_ATTRIBUTE {
    pub aType: CK_ATTRIBUTE_TYPE,
    pub pValue: *const CK_VOID,
    pub ulValueLen: CK_ULONG,
}

/// Defines a date.
#[repr(C)]
pub struct CK_DATE {
    /// The year ("1900" - "9999").
    pub year: [CK_CHAR; 4],

    /// The month ("01" - "12").
    pub month: [CK_CHAR; 2],

    /// The day ("01" - "31").
    pub day: [CK_CHAR; 2],
}

/// Identifies a mechanism type.
///
pub type CK_MECHANISM_TYPE = CK_ULONG;

pub const CKM_RSA_PKCS_KEY_PAIR_GEN      : CK_MECHANISM_TYPE = 0x00000000;
pub const CKM_RSA_PKCS                   : CK_MECHANISM_TYPE = 0x00000001;
pub const CKM_RSA_9796                   : CK_MECHANISM_TYPE = 0x00000002;
pub const CKM_RSA_X_509                  : CK_MECHANISM_TYPE = 0x00000003;

pub const CKM_MD2_RSA_PKCS               : CK_MECHANISM_TYPE = 0x00000004;
pub const CKM_MD5_RSA_PKCS               : CK_MECHANISM_TYPE = 0x00000005;
pub const CKM_SHA1_RSA_PKCS              : CK_MECHANISM_TYPE = 0x00000006;

pub const CKM_RIPEMD128_RSA_PKCS         : CK_MECHANISM_TYPE = 0x00000007;
pub const CKM_RIPEMD160_RSA_PKCS         : CK_MECHANISM_TYPE = 0x00000008;
pub const CKM_RSA_PKCS_OAEP              : CK_MECHANISM_TYPE = 0x00000009;

pub const CKM_RSA_X9_31_KEY_PAIR_GEN     : CK_MECHANISM_TYPE = 0x0000000A;
pub const CKM_RSA_X9_31                  : CK_MECHANISM_TYPE = 0x0000000B;
pub const CKM_SHA1_RSA_X9_31             : CK_MECHANISM_TYPE = 0x0000000C;
pub const CKM_RSA_PKCS_PSS               : CK_MECHANISM_TYPE = 0x0000000D;
pub const CKM_SHA1_RSA_PKCS_PSS          : CK_MECHANISM_TYPE = 0x0000000E;

pub const CKM_DSA_KEY_PAIR_GEN           : CK_MECHANISM_TYPE = 0x00000010;
pub const CKM_DSA                        : CK_MECHANISM_TYPE = 0x00000011;
pub const CKM_DSA_SHA1                   : CK_MECHANISM_TYPE = 0x00000012;
pub const CKM_DSA_SHA224                 : CK_MECHANISM_TYPE = 0x00000013;
pub const CKM_DSA_SHA256                 : CK_MECHANISM_TYPE = 0x00000014;
pub const CKM_DSA_SHA384                 : CK_MECHANISM_TYPE = 0x00000015;
pub const CKM_DSA_SHA512                 : CK_MECHANISM_TYPE = 0x00000016;

pub const CKM_DH_PKCS_KEY_PAIR_GEN       : CK_MECHANISM_TYPE = 0x00000020;
pub const CKM_DH_PKCS_DERIVE             : CK_MECHANISM_TYPE = 0x00000021;

pub const CKM_X9_42_DH_KEY_PAIR_GEN      : CK_MECHANISM_TYPE = 0x00000030;
pub const CKM_X9_42_DH_DERIVE            : CK_MECHANISM_TYPE = 0x00000031;
pub const CKM_X9_42_DH_HYBRID_DERIVE     : CK_MECHANISM_TYPE = 0x00000032;
pub const CKM_X9_42_MQV_DERIVE           : CK_MECHANISM_TYPE = 0x00000033;

pub const CKM_SHA256_RSA_PKCS            : CK_MECHANISM_TYPE = 0x00000040;
pub const CKM_SHA384_RSA_PKCS            : CK_MECHANISM_TYPE = 0x00000041;
pub const CKM_SHA512_RSA_PKCS            : CK_MECHANISM_TYPE = 0x00000042;
pub const CKM_SHA256_RSA_PKCS_PSS        : CK_MECHANISM_TYPE = 0x00000043;
pub const CKM_SHA384_RSA_PKCS_PSS        : CK_MECHANISM_TYPE = 0x00000044;
pub const CKM_SHA512_RSA_PKCS_PSS        : CK_MECHANISM_TYPE = 0x00000045;

pub const CKM_SHA224_RSA_PKCS            : CK_MECHANISM_TYPE = 0x00000046;
pub const CKM_SHA224_RSA_PKCS_PSS        : CK_MECHANISM_TYPE = 0x00000047;

pub const CKM_SHA512_224                 : CK_MECHANISM_TYPE = 0x00000048;
pub const CKM_SHA512_224_HMAC            : CK_MECHANISM_TYPE = 0x00000049;
pub const CKM_SHA512_224_HMAC_GENERAL    : CK_MECHANISM_TYPE = 0x0000004A;
pub const CKM_SHA512_224_KEY_DERIVATION  : CK_MECHANISM_TYPE = 0x0000004B;
pub const CKM_SHA512_256                 : CK_MECHANISM_TYPE = 0x0000004C;
pub const CKM_SHA512_256_HMAC            : CK_MECHANISM_TYPE = 0x0000004D;
pub const CKM_SHA512_256_HMAC_GENERAL    : CK_MECHANISM_TYPE = 0x0000004E;
pub const CKM_SHA512_256_KEY_DERIVATION  : CK_MECHANISM_TYPE = 0x0000004F;

pub const CKM_SHA512_T                   : CK_MECHANISM_TYPE = 0x00000050;
pub const CKM_SHA512_T_HMAC              : CK_MECHANISM_TYPE = 0x00000051;
pub const CKM_SHA512_T_HMAC_GENERAL      : CK_MECHANISM_TYPE = 0x00000052;
pub const CKM_SHA512_T_KEY_DERIVATION    : CK_MECHANISM_TYPE = 0x00000053;

pub const CKM_RC2_KEY_GEN                : CK_MECHANISM_TYPE = 0x00000100;
pub const CKM_RC2_ECB                    : CK_MECHANISM_TYPE = 0x00000101;
pub const CKM_RC2_CBC                    : CK_MECHANISM_TYPE = 0x00000102;
pub const CKM_RC2_MAC                    : CK_MECHANISM_TYPE = 0x00000103;

pub const CKM_RC2_MAC_GENERAL            : CK_MECHANISM_TYPE = 0x00000104;
pub const CKM_RC2_CBC_PAD                : CK_MECHANISM_TYPE = 0x00000105;

pub const CKM_RC4_KEY_GEN                : CK_MECHANISM_TYPE = 0x00000110;
pub const CKM_RC4                        : CK_MECHANISM_TYPE = 0x00000111;
pub const CKM_DES_KEY_GEN                : CK_MECHANISM_TYPE = 0x00000120;
pub const CKM_DES_ECB                    : CK_MECHANISM_TYPE = 0x00000121;
pub const CKM_DES_CBC                    : CK_MECHANISM_TYPE = 0x00000122;
pub const CKM_DES_MAC                    : CK_MECHANISM_TYPE = 0x00000123;

pub const CKM_DES_MAC_GENERAL            : CK_MECHANISM_TYPE = 0x00000124;
pub const CKM_DES_CBC_PAD                : CK_MECHANISM_TYPE = 0x00000125;

pub const CKM_DES2_KEY_GEN               : CK_MECHANISM_TYPE = 0x00000130;
pub const CKM_DES3_KEY_GEN               : CK_MECHANISM_TYPE = 0x00000131;
pub const CKM_DES3_ECB                   : CK_MECHANISM_TYPE = 0x00000132;
pub const CKM_DES3_CBC                   : CK_MECHANISM_TYPE = 0x00000133;
pub const CKM_DES3_MAC                   : CK_MECHANISM_TYPE = 0x00000134;

pub const CKM_DES3_MAC_GENERAL           : CK_MECHANISM_TYPE = 0x00000135;
pub const CKM_DES3_CBC_PAD               : CK_MECHANISM_TYPE = 0x00000136;
pub const CKM_DES3_CMAC_GENERAL          : CK_MECHANISM_TYPE = 0x00000137;
pub const CKM_DES3_CMAC                  : CK_MECHANISM_TYPE = 0x00000138;
pub const CKM_CDMF_KEY_GEN               : CK_MECHANISM_TYPE = 0x00000140;
pub const CKM_CDMF_ECB                   : CK_MECHANISM_TYPE = 0x00000141;
pub const CKM_CDMF_CBC                   : CK_MECHANISM_TYPE = 0x00000142;
pub const CKM_CDMF_MAC                   : CK_MECHANISM_TYPE = 0x00000143;
pub const CKM_CDMF_MAC_GENERAL           : CK_MECHANISM_TYPE = 0x00000144;
pub const CKM_CDMF_CBC_PAD               : CK_MECHANISM_TYPE = 0x00000145;

pub const CKM_DES_OFB64                  : CK_MECHANISM_TYPE = 0x00000150;
pub const CKM_DES_OFB8                   : CK_MECHANISM_TYPE = 0x00000151;
pub const CKM_DES_CFB64                  : CK_MECHANISM_TYPE = 0x00000152;
pub const CKM_DES_CFB8                   : CK_MECHANISM_TYPE = 0x00000153;

pub const CKM_MD2                        : CK_MECHANISM_TYPE = 0x00000200;

pub const CKM_MD2_HMAC                   : CK_MECHANISM_TYPE = 0x00000201;
pub const CKM_MD2_HMAC_GENERAL           : CK_MECHANISM_TYPE = 0x00000202;

pub const CKM_MD5                        : CK_MECHANISM_TYPE = 0x00000210;

pub const CKM_MD5_HMAC                   : CK_MECHANISM_TYPE = 0x00000211;
pub const CKM_MD5_HMAC_GENERAL           : CK_MECHANISM_TYPE = 0x00000212;

pub const CKM_SHA_1                      : CK_MECHANISM_TYPE = 0x00000220;

pub const CKM_SHA_1_HMAC                 : CK_MECHANISM_TYPE = 0x00000221;
pub const CKM_SHA_1_HMAC_GENERAL         : CK_MECHANISM_TYPE = 0x00000222;

pub const CKM_RIPEMD128                  : CK_MECHANISM_TYPE = 0x00000230;
pub const CKM_RIPEMD128_HMAC             : CK_MECHANISM_TYPE = 0x00000231;
pub const CKM_RIPEMD128_HMAC_GENERAL     : CK_MECHANISM_TYPE = 0x00000232;
pub const CKM_RIPEMD160                  : CK_MECHANISM_TYPE = 0x00000240;
pub const CKM_RIPEMD160_HMAC             : CK_MECHANISM_TYPE = 0x00000241;
pub const CKM_RIPEMD160_HMAC_GENERAL     : CK_MECHANISM_TYPE = 0x00000242;

pub const CKM_SHA256                     : CK_MECHANISM_TYPE = 0x00000250;
pub const CKM_SHA256_HMAC                : CK_MECHANISM_TYPE = 0x00000251;
pub const CKM_SHA256_HMAC_GENERAL        : CK_MECHANISM_TYPE = 0x00000252;
pub const CKM_SHA224                     : CK_MECHANISM_TYPE = 0x00000255;
pub const CKM_SHA224_HMAC                : CK_MECHANISM_TYPE = 0x00000256;
pub const CKM_SHA224_HMAC_GENERAL        : CK_MECHANISM_TYPE = 0x00000257;
pub const CKM_SHA384                     : CK_MECHANISM_TYPE = 0x00000260;
pub const CKM_SHA384_HMAC                : CK_MECHANISM_TYPE = 0x00000261;
pub const CKM_SHA384_HMAC_GENERAL        : CK_MECHANISM_TYPE = 0x00000262;
pub const CKM_SHA512                     : CK_MECHANISM_TYPE = 0x00000270;
pub const CKM_SHA512_HMAC                : CK_MECHANISM_TYPE = 0x00000271;
pub const CKM_SHA512_HMAC_GENERAL        : CK_MECHANISM_TYPE = 0x00000272;
pub const CKM_SECURID_KEY_GEN            : CK_MECHANISM_TYPE = 0x00000280;
pub const CKM_SECURID                    : CK_MECHANISM_TYPE = 0x00000282;
pub const CKM_HOTP_KEY_GEN               : CK_MECHANISM_TYPE = 0x00000290;
pub const CKM_HOTP                       : CK_MECHANISM_TYPE = 0x00000291;
pub const CKM_ACTI                       : CK_MECHANISM_TYPE = 0x000002A0;
pub const CKM_ACTI_KEY_GEN               : CK_MECHANISM_TYPE = 0x000002A1;

pub const CKM_CAST_KEY_GEN               : CK_MECHANISM_TYPE = 0x00000300;
pub const CKM_CAST_ECB                   : CK_MECHANISM_TYPE = 0x00000301;
pub const CKM_CAST_CBC                   : CK_MECHANISM_TYPE = 0x00000302;
pub const CKM_CAST_MAC                   : CK_MECHANISM_TYPE = 0x00000303;
pub const CKM_CAST_MAC_GENERAL           : CK_MECHANISM_TYPE = 0x00000304;
pub const CKM_CAST_CBC_PAD               : CK_MECHANISM_TYPE = 0x00000305;
pub const CKM_CAST3_KEY_GEN              : CK_MECHANISM_TYPE = 0x00000310;
pub const CKM_CAST3_ECB                  : CK_MECHANISM_TYPE = 0x00000311;
pub const CKM_CAST3_CBC                  : CK_MECHANISM_TYPE = 0x00000312;
pub const CKM_CAST3_MAC                  : CK_MECHANISM_TYPE = 0x00000313;
pub const CKM_CAST3_MAC_GENERAL          : CK_MECHANISM_TYPE = 0x00000314;
pub const CKM_CAST3_CBC_PAD              : CK_MECHANISM_TYPE = 0x00000315;
/* Note that CAST128 and CAST5 are the same algorithm */
pub const CKM_CAST5_KEY_GEN              : CK_MECHANISM_TYPE = 0x00000320;
pub const CKM_CAST128_KEY_GEN            : CK_MECHANISM_TYPE = 0x00000320;
pub const CKM_CAST5_ECB                  : CK_MECHANISM_TYPE = 0x00000321;
pub const CKM_CAST128_ECB                : CK_MECHANISM_TYPE = 0x00000321;
pub const CKM_CAST5_CBC                  : CK_MECHANISM_TYPE = 0x00000322; /* Deprecated */
pub const CKM_CAST128_CBC                : CK_MECHANISM_TYPE = 0x00000322;
pub const CKM_CAST5_MAC                  : CK_MECHANISM_TYPE = 0x00000323; /* Deprecated */
pub const CKM_CAST128_MAC                : CK_MECHANISM_TYPE = 0x00000323;
pub const CKM_CAST5_MAC_GENERAL          : CK_MECHANISM_TYPE = 0x00000324; /* Deprecated */
pub const CKM_CAST128_MAC_GENERAL        : CK_MECHANISM_TYPE = 0x00000324;
pub const CKM_CAST5_CBC_PAD              : CK_MECHANISM_TYPE = 0x00000325; /* Deprecated */
pub const CKM_CAST128_CBC_PAD            : CK_MECHANISM_TYPE = 0x00000325;
pub const CKM_RC5_KEY_GEN                : CK_MECHANISM_TYPE = 0x00000330;
pub const CKM_RC5_ECB                    : CK_MECHANISM_TYPE = 0x00000331;
pub const CKM_RC5_CBC                    : CK_MECHANISM_TYPE = 0x00000332;
pub const CKM_RC5_MAC                    : CK_MECHANISM_TYPE = 0x00000333;
pub const CKM_RC5_MAC_GENERAL            : CK_MECHANISM_TYPE = 0x00000334;
pub const CKM_RC5_CBC_PAD                : CK_MECHANISM_TYPE = 0x00000335;
pub const CKM_IDEA_KEY_GEN               : CK_MECHANISM_TYPE = 0x00000340;
pub const CKM_IDEA_ECB                   : CK_MECHANISM_TYPE = 0x00000341;
pub const CKM_IDEA_CBC                   : CK_MECHANISM_TYPE = 0x00000342;
pub const CKM_IDEA_MAC                   : CK_MECHANISM_TYPE = 0x00000343;
pub const CKM_IDEA_MAC_GENERAL           : CK_MECHANISM_TYPE = 0x00000344;
pub const CKM_IDEA_CBC_PAD               : CK_MECHANISM_TYPE = 0x00000345;
pub const CKM_GENERIC_SECRET_KEY_GEN     : CK_MECHANISM_TYPE = 0x00000350;
pub const CKM_CONCATENATE_BASE_AND_KEY   : CK_MECHANISM_TYPE = 0x00000360;
pub const CKM_CONCATENATE_BASE_AND_DATA  : CK_MECHANISM_TYPE = 0x00000362;
pub const CKM_CONCATENATE_DATA_AND_BASE  : CK_MECHANISM_TYPE = 0x00000363;
pub const CKM_XOR_BASE_AND_DATA          : CK_MECHANISM_TYPE = 0x00000364;
pub const CKM_EXTRACT_KEY_FROM_KEY       : CK_MECHANISM_TYPE = 0x00000365;
pub const CKM_SSL3_PRE_MASTER_KEY_GEN    : CK_MECHANISM_TYPE = 0x00000370;
pub const CKM_SSL3_MASTER_KEY_DERIVE     : CK_MECHANISM_TYPE = 0x00000371;
pub const CKM_SSL3_KEY_AND_MAC_DERIVE    : CK_MECHANISM_TYPE = 0x00000372;

pub const CKM_SSL3_MASTER_KEY_DERIVE_DH  : CK_MECHANISM_TYPE = 0x00000373;
pub const CKM_TLS_PRE_MASTER_KEY_GEN     : CK_MECHANISM_TYPE = 0x00000374;
pub const CKM_TLS_MASTER_KEY_DERIVE      : CK_MECHANISM_TYPE = 0x00000375;
pub const CKM_TLS_KEY_AND_MAC_DERIVE     : CK_MECHANISM_TYPE = 0x00000376;
pub const CKM_TLS_MASTER_KEY_DERIVE_DH   : CK_MECHANISM_TYPE = 0x00000377;

pub const CKM_TLS_PRF                    : CK_MECHANISM_TYPE = 0x00000378;

pub const CKM_SSL3_MD5_MAC               : CK_MECHANISM_TYPE = 0x00000380;
pub const CKM_SSL3_SHA1_MAC              : CK_MECHANISM_TYPE = 0x00000381;
pub const CKM_MD5_KEY_DERIVATION         : CK_MECHANISM_TYPE = 0x00000390;
pub const CKM_MD2_KEY_DERIVATION         : CK_MECHANISM_TYPE = 0x00000391;
pub const CKM_SHA1_KEY_DERIVATION        : CK_MECHANISM_TYPE = 0x00000392;

pub const CKM_SHA256_KEY_DERIVATION      : CK_MECHANISM_TYPE = 0x00000393;
pub const CKM_SHA384_KEY_DERIVATION      : CK_MECHANISM_TYPE = 0x00000394;
pub const CKM_SHA512_KEY_DERIVATION      : CK_MECHANISM_TYPE = 0x00000395;
pub const CKM_SHA224_KEY_DERIVATION      : CK_MECHANISM_TYPE = 0x00000396;

pub const CKM_PBE_MD2_DES_CBC            : CK_MECHANISM_TYPE = 0x000003A0;
pub const CKM_PBE_MD5_DES_CBC            : CK_MECHANISM_TYPE = 0x000003A1;
pub const CKM_PBE_MD5_CAST_CBC           : CK_MECHANISM_TYPE = 0x000003A2;
pub const CKM_PBE_MD5_CAST3_CBC          : CK_MECHANISM_TYPE = 0x000003A3;
pub const CKM_PBE_MD5_CAST5_CBC          : CK_MECHANISM_TYPE = 0x000003A4; /* Deprecated */
pub const CKM_PBE_MD5_CAST128_CBC        : CK_MECHANISM_TYPE = 0x000003A4;
pub const CKM_PBE_SHA1_CAST5_CBC         : CK_MECHANISM_TYPE = 0x000003A5; /* Deprecated */
pub const CKM_PBE_SHA1_CAST128_CBC       : CK_MECHANISM_TYPE = 0x000003A5;
pub const CKM_PBE_SHA1_RC4_128           : CK_MECHANISM_TYPE = 0x000003A6;
pub const CKM_PBE_SHA1_RC4_40            : CK_MECHANISM_TYPE = 0x000003A7;
pub const CKM_PBE_SHA1_DES3_EDE_CBC      : CK_MECHANISM_TYPE = 0x000003A8;
pub const CKM_PBE_SHA1_DES2_EDE_CBC      : CK_MECHANISM_TYPE = 0x000003A9;
pub const CKM_PBE_SHA1_RC2_128_CBC       : CK_MECHANISM_TYPE = 0x000003AA;
pub const CKM_PBE_SHA1_RC2_40_CBC        : CK_MECHANISM_TYPE = 0x000003AB;

pub const CKM_PKCS5_PBKD2                : CK_MECHANISM_TYPE = 0x000003B0;

pub const CKM_PBA_SHA1_WITH_SHA1_HMAC    : CK_MECHANISM_TYPE = 0x000003C0;

pub const CKM_WTLS_PRE_MASTER_KEY_GEN         : CK_MECHANISM_TYPE = 0x000003D0;
pub const CKM_WTLS_MASTER_KEY_DERIVE          : CK_MECHANISM_TYPE = 0x000003D1;
pub const CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC   : CK_MECHANISM_TYPE = 0x000003D2;
pub const CKM_WTLS_PRF                        : CK_MECHANISM_TYPE = 0x000003D3;
pub const CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE  : CK_MECHANISM_TYPE = 0x000003D4;
pub const CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE  : CK_MECHANISM_TYPE = 0x000003D5;

pub const CKM_TLS10_MAC_SERVER                : CK_MECHANISM_TYPE = 0x000003D6;
pub const CKM_TLS10_MAC_CLIENT                : CK_MECHANISM_TYPE = 0x000003D7;
pub const CKM_TLS12_MAC                       : CK_MECHANISM_TYPE = 0x000003D8;
pub const CKM_TLS12_KDF                       : CK_MECHANISM_TYPE = 0x000003D9;
pub const CKM_TLS12_MASTER_KEY_DERIVE         : CK_MECHANISM_TYPE = 0x000003E0;
pub const CKM_TLS12_KEY_AND_MAC_DERIVE        : CK_MECHANISM_TYPE = 0x000003E1;
pub const CKM_TLS12_MASTER_KEY_DERIVE_DH      : CK_MECHANISM_TYPE = 0x000003E2;
pub const CKM_TLS12_KEY_SAFE_DERIVE           : CK_MECHANISM_TYPE = 0x000003E3;
pub const CKM_TLS_MAC                         : CK_MECHANISM_TYPE = 0x000003E4;
pub const CKM_TLS_KDF                         : CK_MECHANISM_TYPE = 0x000003E5;

pub const CKM_KEY_WRAP_LYNKS             : CK_MECHANISM_TYPE = 0x00000400;
pub const CKM_KEY_WRAP_SET_OAEP          : CK_MECHANISM_TYPE = 0x00000401;

pub const CKM_CMS_SIG                    : CK_MECHANISM_TYPE = 0x00000500;
pub const CKM_KIP_DERIVE                 : CK_MECHANISM_TYPE = 0x00000510;
pub const CKM_KIP_WRAP                   : CK_MECHANISM_TYPE = 0x00000511;
pub const CKM_KIP_MAC                    : CK_MECHANISM_TYPE = 0x00000512;

pub const CKM_CAMELLIA_KEY_GEN           : CK_MECHANISM_TYPE = 0x00000550;
pub const CKM_CAMELLIA_ECB               : CK_MECHANISM_TYPE = 0x00000551;
pub const CKM_CAMELLIA_CBC               : CK_MECHANISM_TYPE = 0x00000552;
pub const CKM_CAMELLIA_MAC               : CK_MECHANISM_TYPE = 0x00000553;
pub const CKM_CAMELLIA_MAC_GENERAL       : CK_MECHANISM_TYPE = 0x00000554;
pub const CKM_CAMELLIA_CBC_PAD           : CK_MECHANISM_TYPE = 0x00000555;
pub const CKM_CAMELLIA_ECB_ENCRYPT_DATA  : CK_MECHANISM_TYPE = 0x00000556;
pub const CKM_CAMELLIA_CBC_ENCRYPT_DATA  : CK_MECHANISM_TYPE = 0x00000557;
pub const CKM_CAMELLIA_CTR               : CK_MECHANISM_TYPE = 0x00000558;

pub const CKM_ARIA_KEY_GEN               : CK_MECHANISM_TYPE = 0x00000560;
pub const CKM_ARIA_ECB                   : CK_MECHANISM_TYPE = 0x00000561;
pub const CKM_ARIA_CBC                   : CK_MECHANISM_TYPE = 0x00000562;
pub const CKM_ARIA_MAC                   : CK_MECHANISM_TYPE = 0x00000563;
pub const CKM_ARIA_MAC_GENERAL           : CK_MECHANISM_TYPE = 0x00000564;
pub const CKM_ARIA_CBC_PAD               : CK_MECHANISM_TYPE = 0x00000565;
pub const CKM_ARIA_ECB_ENCRYPT_DATA      : CK_MECHANISM_TYPE = 0x00000566;
pub const CKM_ARIA_CBC_ENCRYPT_DATA      : CK_MECHANISM_TYPE = 0x00000567;

pub const CKM_SEED_KEY_GEN               : CK_MECHANISM_TYPE = 0x00000650;
pub const CKM_SEED_ECB                   : CK_MECHANISM_TYPE = 0x00000651;
pub const CKM_SEED_CBC                   : CK_MECHANISM_TYPE = 0x00000652;
pub const CKM_SEED_MAC                   : CK_MECHANISM_TYPE = 0x00000653;
pub const CKM_SEED_MAC_GENERAL           : CK_MECHANISM_TYPE = 0x00000654;
pub const CKM_SEED_CBC_PAD               : CK_MECHANISM_TYPE = 0x00000655;
pub const CKM_SEED_ECB_ENCRYPT_DATA      : CK_MECHANISM_TYPE = 0x00000656;
pub const CKM_SEED_CBC_ENCRYPT_DATA      : CK_MECHANISM_TYPE = 0x00000657;

pub const CKM_SKIPJACK_KEY_GEN           : CK_MECHANISM_TYPE = 0x00001000;
pub const CKM_SKIPJACK_ECB64             : CK_MECHANISM_TYPE = 0x00001001;
pub const CKM_SKIPJACK_CBC64             : CK_MECHANISM_TYPE = 0x00001002;
pub const CKM_SKIPJACK_OFB64             : CK_MECHANISM_TYPE = 0x00001003;
pub const CKM_SKIPJACK_CFB64             : CK_MECHANISM_TYPE = 0x00001004;
pub const CKM_SKIPJACK_CFB32             : CK_MECHANISM_TYPE = 0x00001005;
pub const CKM_SKIPJACK_CFB16             : CK_MECHANISM_TYPE = 0x00001006;
pub const CKM_SKIPJACK_CFB8              : CK_MECHANISM_TYPE = 0x00001007;
pub const CKM_SKIPJACK_WRAP              : CK_MECHANISM_TYPE = 0x00001008;
pub const CKM_SKIPJACK_PRIVATE_WRAP      : CK_MECHANISM_TYPE = 0x00001009;
pub const CKM_SKIPJACK_RELAYX            : CK_MECHANISM_TYPE = 0x0000100a;
pub const CKM_KEA_KEY_PAIR_GEN           : CK_MECHANISM_TYPE = 0x00001010;
pub const CKM_KEA_KEY_DERIVE             : CK_MECHANISM_TYPE = 0x00001011;
pub const CKM_KEA_DERIVE                 : CK_MECHANISM_TYPE = 0x00001012;
pub const CKM_FORTEZZA_TIMESTAMP         : CK_MECHANISM_TYPE = 0x00001020;
pub const CKM_BATON_KEY_GEN              : CK_MECHANISM_TYPE = 0x00001030;
pub const CKM_BATON_ECB128               : CK_MECHANISM_TYPE = 0x00001031;
pub const CKM_BATON_ECB96                : CK_MECHANISM_TYPE = 0x00001032;
pub const CKM_BATON_CBC128               : CK_MECHANISM_TYPE = 0x00001033;
pub const CKM_BATON_COUNTER              : CK_MECHANISM_TYPE = 0x00001034;
pub const CKM_BATON_SHUFFLE              : CK_MECHANISM_TYPE = 0x00001035;
pub const CKM_BATON_WRAP                 : CK_MECHANISM_TYPE = 0x00001036;

pub const CKM_ECDSA_KEY_PAIR_GEN         : CK_MECHANISM_TYPE = 0x00001040; /* Deprecated */
pub const CKM_EC_KEY_PAIR_GEN            : CK_MECHANISM_TYPE = 0x00001040;

pub const CKM_ECDSA                      : CK_MECHANISM_TYPE = 0x00001041;
pub const CKM_ECDSA_SHA1                 : CK_MECHANISM_TYPE = 0x00001042;
pub const CKM_ECDSA_SHA224               : CK_MECHANISM_TYPE = 0x00001043;
pub const CKM_ECDSA_SHA256               : CK_MECHANISM_TYPE = 0x00001044;
pub const CKM_ECDSA_SHA384               : CK_MECHANISM_TYPE = 0x00001045;
pub const CKM_ECDSA_SHA512               : CK_MECHANISM_TYPE = 0x00001046;

pub const CKM_ECDH1_DERIVE               : CK_MECHANISM_TYPE = 0x00001050;
pub const CKM_ECDH1_COFACTOR_DERIVE      : CK_MECHANISM_TYPE = 0x00001051;
pub const CKM_ECMQV_DERIVE               : CK_MECHANISM_TYPE = 0x00001052;

pub const CKM_ECDH_AES_KEY_WRAP          : CK_MECHANISM_TYPE = 0x00001053;
pub const CKM_RSA_AES_KEY_WRAP           : CK_MECHANISM_TYPE = 0x00001054;

pub const CKM_JUNIPER_KEY_GEN            : CK_MECHANISM_TYPE = 0x00001060;
pub const CKM_JUNIPER_ECB128             : CK_MECHANISM_TYPE = 0x00001061;
pub const CKM_JUNIPER_CBC128             : CK_MECHANISM_TYPE = 0x00001062;
pub const CKM_JUNIPER_COUNTER            : CK_MECHANISM_TYPE = 0x00001063;
pub const CKM_JUNIPER_SHUFFLE            : CK_MECHANISM_TYPE = 0x00001064;
pub const CKM_JUNIPER_WRAP               : CK_MECHANISM_TYPE = 0x00001065;
pub const CKM_FASTHASH                   : CK_MECHANISM_TYPE = 0x00001070;

pub const CKM_AES_KEY_GEN                : CK_MECHANISM_TYPE = 0x00001080;
pub const CKM_AES_ECB                    : CK_MECHANISM_TYPE = 0x00001081;
pub const CKM_AES_CBC                    : CK_MECHANISM_TYPE = 0x00001082;
pub const CKM_AES_MAC                    : CK_MECHANISM_TYPE = 0x00001083;
pub const CKM_AES_MAC_GENERAL            : CK_MECHANISM_TYPE = 0x00001084;
pub const CKM_AES_CBC_PAD                : CK_MECHANISM_TYPE = 0x00001085;
pub const CKM_AES_CTR                    : CK_MECHANISM_TYPE = 0x00001086;
pub const CKM_AES_GCM                    : CK_MECHANISM_TYPE = 0x00001087;
pub const CKM_AES_CCM                    : CK_MECHANISM_TYPE = 0x00001088;
pub const CKM_AES_CTS                    : CK_MECHANISM_TYPE = 0x00001089;
pub const CKM_AES_CMAC                   : CK_MECHANISM_TYPE = 0x0000108A;
pub const CKM_AES_CMAC_GENERAL           : CK_MECHANISM_TYPE = 0x0000108B;

pub const CKM_AES_XCBC_MAC               : CK_MECHANISM_TYPE = 0x0000108C;
pub const CKM_AES_XCBC_MAC_96            : CK_MECHANISM_TYPE = 0x0000108D;
pub const CKM_AES_GMAC                   : CK_MECHANISM_TYPE = 0x0000108E;

pub const CKM_BLOWFISH_KEY_GEN           : CK_MECHANISM_TYPE = 0x00001090;
pub const CKM_BLOWFISH_CBC               : CK_MECHANISM_TYPE = 0x00001091;
pub const CKM_TWOFISH_KEY_GEN            : CK_MECHANISM_TYPE = 0x00001092;
pub const CKM_TWOFISH_CBC                : CK_MECHANISM_TYPE = 0x00001093;
pub const CKM_BLOWFISH_CBC_PAD           : CK_MECHANISM_TYPE = 0x00001094;
pub const CKM_TWOFISH_CBC_PAD            : CK_MECHANISM_TYPE = 0x00001095;

pub const CKM_DES_ECB_ENCRYPT_DATA       : CK_MECHANISM_TYPE = 0x00001100;
pub const CKM_DES_CBC_ENCRYPT_DATA       : CK_MECHANISM_TYPE = 0x00001101;
pub const CKM_DES3_ECB_ENCRYPT_DATA      : CK_MECHANISM_TYPE = 0x00001102;
pub const CKM_DES3_CBC_ENCRYPT_DATA      : CK_MECHANISM_TYPE = 0x00001103;
pub const CKM_AES_ECB_ENCRYPT_DATA       : CK_MECHANISM_TYPE = 0x00001104;
pub const CKM_AES_CBC_ENCRYPT_DATA       : CK_MECHANISM_TYPE = 0x00001105;

pub const CKM_GOSTR3410_KEY_PAIR_GEN     : CK_MECHANISM_TYPE = 0x00001200;
pub const CKM_GOSTR3410                  : CK_MECHANISM_TYPE = 0x00001201;
pub const CKM_GOSTR3410_WITH_GOSTR3411   : CK_MECHANISM_TYPE = 0x00001202;
pub const CKM_GOSTR3410_KEY_WRAP         : CK_MECHANISM_TYPE = 0x00001203;
pub const CKM_GOSTR3410_DERIVE           : CK_MECHANISM_TYPE = 0x00001204;
pub const CKM_GOSTR3411                  : CK_MECHANISM_TYPE = 0x00001210;
pub const CKM_GOSTR3411_HMAC             : CK_MECHANISM_TYPE = 0x00001211;
pub const CKM_GOST28147_KEY_GEN          : CK_MECHANISM_TYPE = 0x00001220;
pub const CKM_GOST28147_ECB              : CK_MECHANISM_TYPE = 0x00001221;
pub const CKM_GOST28147                  : CK_MECHANISM_TYPE = 0x00001222;
pub const CKM_GOST28147_MAC              : CK_MECHANISM_TYPE = 0x00001223;
pub const CKM_GOST28147_KEY_WRAP         : CK_MECHANISM_TYPE = 0x00001224;

pub const CKM_DSA_PARAMETER_GEN          : CK_MECHANISM_TYPE = 0x00002000;
pub const CKM_DH_PKCS_PARAMETER_GEN      : CK_MECHANISM_TYPE = 0x00002001;
pub const CKM_X9_42_DH_PARAMETER_GEN     : CK_MECHANISM_TYPE = 0x00002002;
pub const CKM_DSA_PROBABLISTIC_PARAMETER_GEN    : CK_MECHANISM_TYPE = 0x00002003;
pub const CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN    : CK_MECHANISM_TYPE = 0x00002004;

pub const CKM_AES_OFB                    : CK_MECHANISM_TYPE = 0x00002104;
pub const CKM_AES_CFB64                  : CK_MECHANISM_TYPE = 0x00002105;
pub const CKM_AES_CFB8                   : CK_MECHANISM_TYPE = 0x00002106;
pub const CKM_AES_CFB128                 : CK_MECHANISM_TYPE = 0x00002107;

pub const CKM_AES_CFB1                   : CK_MECHANISM_TYPE = 0x00002108;
pub const CKM_AES_KEY_WRAP               : CK_MECHANISM_TYPE = 0x00002109;     /* WAS: 0x00001090 */
pub const CKM_AES_KEY_WRAP_PAD           : CK_MECHANISM_TYPE = 0x0000210A;     /* WAS: 0x00001091 */

pub const CKM_RSA_PKCS_TPM_1_1           : CK_MECHANISM_TYPE = 0x00004001;
pub const CKM_RSA_PKCS_OAEP_TPM_1_1      : CK_MECHANISM_TYPE = 0x00004002;

pub const CKM_VENDOR_DEFINED             : CK_MECHANISM_TYPE = 0x80000000;

/// Specifies a particular mechanism
#[repr(C)]
pub struct CK_MECHANISM {
    pub mechanism: CK_MECHANISM_TYPE,
    pub pParameter: *const CK_VOID,
    pub ulParameterLen: CK_ULONG,
}

/// Provides information about a partiuclar mechanism
#[repr(C)]
pub struct CK_MECHANISM_INFO {
    pub ulMinKeySize: CK_ULONG,
    pub ulMaxKeySize: CK_ULONG,
    pub flags: CK_FLAGS,
}

// Flags
/// Performed by hardware.
pub const CKF_HW: CK_FLAGS = 0x00000001;

// Specify whether or not a mechanism cna be used for a task:
pub const CKF_ENCRYPT            : CK_FLAGS = 0x00000100;
pub const CKF_DECRYPT            : CK_FLAGS = 0x00000200;
pub const CKF_DIGEST             : CK_FLAGS = 0x00000400;
pub const CKF_SIGN               : CK_FLAGS = 0x00000800;
pub const CKF_SIGN_RECOVER       : CK_FLAGS = 0x00001000;
pub const CKF_VERIFY             : CK_FLAGS = 0x00002000;
pub const CKF_VERIFY_RECOVER     : CK_FLAGS = 0x00004000;
pub const CKF_GENERATE           : CK_FLAGS = 0x00008000;
pub const CKF_GENERATE_KEY_PAIR  : CK_FLAGS = 0x00010000;
pub const CKF_WRAP               : CK_FLAGS = 0x00020000;
pub const CKF_UNWRAP             : CK_FLAGS = 0x00040000;
pub const CKF_DERIVE             : CK_FLAGS = 0x00080000;

// Describe a token’s EC capabilities not available in mechanism information
pub const CKF_EC_F_P             : CK_FLAGS = 0x00100000;
pub const CKF_EC_F_2M            : CK_FLAGS = 0x00200000;
pub const CKF_EC_ECPARAMETERS    : CK_FLAGS = 0x00400000;
pub const CKF_EC_NAMEDCURVE      : CK_FLAGS = 0x00800000;
pub const CKF_EC_UNCOMPRESS      : CK_FLAGS = 0x01000000;
pub const CKF_EC_COMPRESS        : CK_FLAGS = 0x02000000;

pub const CKF_EXTENSION          : CK_FLAGS = 0x80000000;

/// The return value of a Cryptoki function.
pub type CK_RV = CK_ULONG;

pub const CKR_OK                                : CK_RV = 0x00000000;
pub const CKR_CANCEL                            : CK_RV = 0x00000001;
pub const CKR_HOST_MEMORY                       : CK_RV = 0x00000002;
pub const CKR_SLOT_ID_INVALID                   : CK_RV = 0x00000003;

pub const CKR_GENERAL_ERROR                     : CK_RV = 0x00000005;
pub const CKR_FUNCTION_FAILED                   : CK_RV = 0x00000006;

pub const CKR_ARGUMENTS_BAD                     : CK_RV = 0x00000007;
pub const CKR_NO_EVENT                          : CK_RV = 0x00000008;
pub const CKR_NEED_TO_CREATE_THREADS            : CK_RV = 0x00000009;
pub const CKR_CANT_LOCK                         : CK_RV = 0x0000000A;

pub const CKR_ATTRIBUTE_READ_ONLY               : CK_RV = 0x00000010;
pub const CKR_ATTRIBUTE_SENSITIVE               : CK_RV = 0x00000011;
pub const CKR_ATTRIBUTE_TYPE_INVALID            : CK_RV = 0x00000012;
pub const CKR_ATTRIBUTE_VALUE_INVALID           : CK_RV = 0x00000013;

pub const CKR_ACTION_PROHIBITED                 : CK_RV = 0x0000001B;

pub const CKR_DATA_INVALID                      : CK_RV = 0x00000020;
pub const CKR_DATA_LEN_RANGE                    : CK_RV = 0x00000021;
pub const CKR_DEVICE_ERROR                      : CK_RV = 0x00000030;
pub const CKR_DEVICE_MEMORY                     : CK_RV = 0x00000031;
pub const CKR_DEVICE_REMOVED                    : CK_RV = 0x00000032;
pub const CKR_ENCRYPTED_DATA_INVALID            : CK_RV = 0x00000040;
pub const CKR_ENCRYPTED_DATA_LEN_RANGE          : CK_RV = 0x00000041;
pub const CKR_FUNCTION_CANCELED                 : CK_RV = 0x00000050;
pub const CKR_FUNCTION_NOT_PARALLEL             : CK_RV = 0x00000051;

pub const CKR_FUNCTION_NOT_SUPPORTED            : CK_RV = 0x00000054;

pub const CKR_KEY_HANDLE_INVALID                : CK_RV = 0x00000060;

pub const CKR_KEY_SIZE_RANGE                    : CK_RV = 0x00000062;
pub const CKR_KEY_TYPE_INCONSISTENT             : CK_RV = 0x00000063;

pub const CKR_KEY_NOT_NEEDED                    : CK_RV = 0x00000064;
pub const CKR_KEY_CHANGED                       : CK_RV = 0x00000065;
pub const CKR_KEY_NEEDED                        : CK_RV = 0x00000066;
pub const CKR_KEY_INDIGESTIBLE                  : CK_RV = 0x00000067;
pub const CKR_KEY_FUNCTION_NOT_PERMITTED        : CK_RV = 0x00000068;
pub const CKR_KEY_NOT_WRAPPABLE                 : CK_RV = 0x00000069;
pub const CKR_KEY_UNEXTRACTABLE                 : CK_RV = 0x0000006A;

pub const CKR_MECHANISM_INVALID                 : CK_RV = 0x00000070;
pub const CKR_MECHANISM_PARAM_INVALID           : CK_RV = 0x00000071;

pub const CKR_OBJECT_HANDLE_INVALID             : CK_RV = 0x00000082;
pub const CKR_OPERATION_ACTIVE                  : CK_RV = 0x00000090;
pub const CKR_OPERATION_NOT_INITIALIZED         : CK_RV = 0x00000091;
pub const CKR_PIN_INCORRECT                     : CK_RV = 0x000000A0;
pub const CKR_PIN_INVALID                       : CK_RV = 0x000000A1;
pub const CKR_PIN_LEN_RANGE                     : CK_RV = 0x000000A2;

pub const CKR_PIN_EXPIRED                       : CK_RV = 0x000000A3;
pub const CKR_PIN_LOCKED                        : CK_RV = 0x000000A4;

pub const CKR_SESSION_CLOSED                    : CK_RV = 0x000000B0;
pub const CKR_SESSION_COUNT                     : CK_RV = 0x000000B1;
pub const CKR_SESSION_HANDLE_INVALID            : CK_RV = 0x000000B3;
pub const CKR_SESSION_PARALLEL_NOT_SUPPORTED    : CK_RV = 0x000000B4;
pub const CKR_SESSION_READ_ONLY                 : CK_RV = 0x000000B5;
pub const CKR_SESSION_EXISTS                    : CK_RV = 0x000000B6;

pub const CKR_SESSION_READ_ONLY_EXISTS          : CK_RV = 0x000000B7;
pub const CKR_SESSION_READ_WRITE_SO_EXISTS      : CK_RV = 0x000000B8;

pub const CKR_SIGNATURE_INVALID                 : CK_RV = 0x000000C0;
pub const CKR_SIGNATURE_LEN_RANGE               : CK_RV = 0x000000C1;
pub const CKR_TEMPLATE_INCOMPLETE               : CK_RV = 0x000000D0;
pub const CKR_TEMPLATE_INCONSISTENT             : CK_RV = 0x000000D1;
pub const CKR_TOKEN_NOT_PRESENT                 : CK_RV = 0x000000E0;
pub const CKR_TOKEN_NOT_RECOGNIZED              : CK_RV = 0x000000E1;
pub const CKR_TOKEN_WRITE_PROTECTED             : CK_RV = 0x000000E2;
pub const CKR_UNWRAPPING_KEY_HANDLE_INVALID     : CK_RV = 0x000000F0;
pub const CKR_UNWRAPPING_KEY_SIZE_RANGE         : CK_RV = 0x000000F1;
pub const CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT  : CK_RV = 0x000000F2;
pub const CKR_USER_ALREADY_LOGGED_IN            : CK_RV = 0x00000100;
pub const CKR_USER_NOT_LOGGED_IN                : CK_RV = 0x00000101;
pub const CKR_USER_PIN_NOT_INITIALIZED          : CK_RV = 0x00000102;
pub const CKR_USER_TYPE_INVALID                 : CK_RV = 0x00000103;

pub const CKR_USER_ANOTHER_ALREADY_LOGGED_IN    : CK_RV = 0x00000104;
pub const CKR_USER_TOO_MANY_TYPES               : CK_RV = 0x00000105;

pub const CKR_WRAPPED_KEY_INVALID               : CK_RV = 0x00000110;
pub const CKR_WRAPPED_KEY_LEN_RANGE             : CK_RV = 0x00000112;
pub const CKR_WRAPPING_KEY_HANDLE_INVALID       : CK_RV = 0x00000113;
pub const CKR_WRAPPING_KEY_SIZE_RANGE           : CK_RV = 0x00000114;
pub const CKR_WRAPPING_KEY_TYPE_INCONSISTENT    : CK_RV = 0x00000115;
pub const CKR_RANDOM_SEED_NOT_SUPPORTED         : CK_RV = 0x00000120;

pub const CKR_RANDOM_NO_RNG                     : CK_RV = 0x00000121;

pub const CKR_DOMAIN_PARAMS_INVALID             : CK_RV = 0x00000130;

pub const CKR_CURVE_NOT_SUPPORTED               : CK_RV = 0x00000140;

pub const CKR_BUFFER_TOO_SMALL                  : CK_RV = 0x00000150;
pub const CKR_SAVED_STATE_INVALID               : CK_RV = 0x00000160;
pub const CKR_INFORMATION_SENSITIVE             : CK_RV = 0x00000170;
pub const CKR_STATE_UNSAVEABLE                  : CK_RV = 0x00000180;

pub const CKR_CRYPTOKI_NOT_INITIALIZED          : CK_RV = 0x00000190;
pub const CKR_CRYPTOKI_ALREADY_INITIALIZED      : CK_RV = 0x00000191;
pub const CKR_MUTEX_BAD                         : CK_RV = 0x000001A0;
pub const CKR_MUTEX_NOT_LOCKED                  : CK_RV = 0x000001A1;

pub const CKR_NEW_PIN_MODE                      : CK_RV = 0x000001B0;
pub const CKR_NEXT_OTP                          : CK_RV = 0x000001B1;

pub const CKR_EXCEEDED_MAX_ITERATIONS           : CK_RV = 0x000001B5;
pub const CKR_FIPS_SELF_TEST_FAILED             : CK_RV = 0x000001B6;
pub const CKR_LIBRARY_LOAD_FAILED               : CK_RV = 0x000001B7;
pub const CKR_PIN_TOO_WEAK                      : CK_RV = 0x000001B8;
pub const CKR_PUBLIC_KEY_INVALID                : CK_RV = 0x000001B9;

pub const CKR_FUNCTION_REJECTED                 : CK_RV = 0x00000200;

pub const CKR_VENDOR_DEFINED                    : CK_RV = 0x80000000;


/// An application callback that processes events.
pub type CK_NOTIFY = unsafe extern "C" fn(hSession: CK_SESSION_HANDLE,
                                          event: CK_NOTIFICATION,
                                          pApplication: *const CK_VOID)
                                          -> CK_RV;

/// An application callback for creating a mutex object.
pub type CK_CREATEMUTEX = unsafe extern "C" fn(ppMutex: *mut *const CK_VOID)
                                               -> CK_RV;

/// An application callback for destroying a mutex object.
pub type CK_DESTROYMUTEX = unsafe extern "C" fn(pMutex: *const CK_VOID)
                                                -> CK_RV;

/// An application callback for locking a mutex.
pub type CK_LOCKMUTEX = unsafe extern "C" fn(pMutex: *const CK_VOID)
                                             -> CK_RV;

/// An application callback for unlocking a mutex.
pub type CK_UNLOCKMUTEX = unsafe extern "C" fn(pMutex: *const CK_VOID)
                                               -> CK_RV;

/// The optional arguments to `C_Initialize`.
#[repr(C)]
pub struct CK_C_INITIALIZE_ARGS {
    pub CreateMutex: CK_CREATEMUTEX,
    pub DestroyMutex: CK_DESTROYMUTEX,
    pub LockMutex: CK_LOCKMUTEX,
    pub UnlockMutex: CK_UNLOCKMUTEX,
    pub flags: CK_FLAGS,
    pub pReserved: *const CK_VOID,
}

// Flags
pub const CKF_LIBRARY_CANT_CREATE_OS_THREADS: CK_FLAGS = 0x00000001;
pub const CKF_OS_LOCKING_OK: CK_FLAGS = 0x00000002;

// Additional flags for parameters to functions.

/// For `C_WaitForSlotEvent`.
pub const CKF_DONT_BLOCK: CK_FLAGS = 1;

/// RSA PKCS MGF type.
///
/// Indiactes the Message Generation Function applit to a messge block when
/// formatting a message block for the PKCS #1 OAEP encryption scheme.
pub type CK_RSA_PKCS_MGF_TYPE = CK_ULONG;

pub const CKG_MGF1_SHA1         : CK_RSA_PKCS_MGF_TYPE = 0x00000001;
pub const CKG_MGF1_SHA256       : CK_RSA_PKCS_MGF_TYPE = 0x00000002;
pub const CKG_MGF1_SHA384       : CK_RSA_PKCS_MGF_TYPE = 0x00000003;
pub const CKG_MGF1_SHA512       : CK_RSA_PKCS_MGF_TYPE = 0x00000004;
pub const CKG_MGF1_SHA224       : CK_RSA_PKCS_MGF_TYPE = 0x00000005;

/// OEAP source type.
///
/// Indicates the source of the encoding parameter when formatting a message
/// block for the PKCS #1 OAEP encryption scheme.
pub type CK_RSA_PKCS_OAEP_SOURCE_TYPE = CK_ULONG;

pub const CKZ_DATA_SPECIFIED: CK_RSA_PKCS_OAEP_SOURCE_TYPE = 1;

/// The parameters to the `CKM_RSA_PKCS_OAEP` mechanism.
#[repr(C)]
pub struct CK_RSA_PKCS_OAEP_PARAMS {
    pub hashAlg: CK_MECHANISM_TYPE,
    pub mgf: CK_RSA_PKCS_MGF_TYPE,
    pub source: CK_RSA_PKCS_OAEP_SOURCE_TYPE,
    pub pSourceData: *const CK_VOID,
    pub pSourceDataLen: CK_ULONG
}

/// The parameters to the `CKM_RSA_PKCS_PSS` mechanism.
#[repr(C)]
pub struct CK_RSA_PKCS_PSS_PARAMS {
    pub hashAlg: CK_MECHANISM_TYPE,
    pub mgf: CK_RSA_PKCS_MGF_TYPE,
    pub sLen: CK_ULONG,
}

pub type CK_EC_KDF_TYPE = CK_ULONG;

// The following EC Key Derivation Functions are defined:
pub const CKD_NULL                 : CK_EC_KDF_TYPE = 0x00000001;
pub const CKD_SHA1_KDF             : CK_EC_KDF_TYPE = 0x00000002;

// The following X9.42 DH key derivation functions are defined:
pub const CKD_SHA1_KDF_ASN1        : CK_EC_KDF_TYPE = 0x00000003;
pub const CKD_SHA1_KDF_CONCATENATE : CK_EC_KDF_TYPE = 0x00000004;
pub const CKD_SHA224_KDF           : CK_EC_KDF_TYPE = 0x00000005;
pub const CKD_SHA256_KDF           : CK_EC_KDF_TYPE = 0x00000006;
pub const CKD_SHA384_KDF           : CK_EC_KDF_TYPE = 0x00000007;
pub const CKD_SHA512_KDF           : CK_EC_KDF_TYPE = 0x00000008;
pub const CKD_CPDIVERSIFY_KDF      : CK_EC_KDF_TYPE = 0x00000009;

#[repr(C)]
pub struct CK_ECDH1_DERIVE_PARAMS {
    pub kdf: CK_EC_KDF_TYPE,
    pub ulSharedDataLen: CK_ULONG,
    pub pSharedData: *const CK_BYTE,
    pub ulPublicDataLen: CK_ULONG,
    pub pPublicData: *const CK_BYTE,
}

#[repr(C)]
pub struct CK_ECDH2_DERIVE_PARAMS {
    pub kdf: CK_EC_KDF_TYPE,
    pub ulSharedDataLen: CK_ULONG,
    pub pSharedData: *const CK_BYTE,
    pub ulPublicDataLen: CK_ULONG,
    pub pPublicData: *const CK_BYTE,
    pub ulPrivateDataLen: CK_ULONG,
    pub hPrivateData: CK_OBJECT_HANDLE,
    pub ulPublicDataLen2: CK_ULONG,
    pub pPublicData2: *const CK_BYTE,
}

#[repr(C)]
pub struct CK_ECMQV_DERIVE_PARAMS {
    pub kdf: CK_EC_KDF_TYPE,
    pub ulSharedDataLen: CK_ULONG,
    pub pSharedData: *const CK_BYTE,
    pub ulPublicDataLen: CK_ULONG,
    pub pPublicData: *const CK_BYTE,
    pub ulPrivateDataLen: CK_ULONG,
    pub hPrivateData: CK_OBJECT_HANDLE,
    pub ulPublicDataLen2: CK_ULONG,
    pub pPublicData2: *const CK_BYTE,
    pub publicKey: CK_OBJECT_HANDLE,
}

pub type CK_X9_42_DH_KDF_TYPE = CK_ULONG;

#[repr(C)]
pub struct CK_X9_42_DH1_DERIVE_PARAMS {
    pub kdf: CK_X9_42_DH_KDF_TYPE,
    pub ulOtherInfoLen: CK_ULONG,
    pub pOtherInfo: *const CK_BYTE,
    pub ulPublicDataLen: CK_ULONG,
    pub pPublicData: *const CK_BYTE,
}

#[repr(C)]
pub struct CK_X9_42_DH2_DERIVE_PARAMS {
    pub kdf: CK_X9_42_DH_KDF_TYPE,
    pub ulOtherInfoLen: CK_ULONG,
    pub pOtherInfo: *const CK_BYTE,
    pub ulPublicDataLen: CK_ULONG,
    pub pPublicData: *const CK_BYTE,
    pub ulPrivateDataLen: CK_ULONG,
    pub hPrivateData: CK_OBJECT_HANDLE,
    pub ulPublicDataLen2: CK_ULONG,
    pub pPublicData2: *const CK_BYTE,
}

#[repr(C)]
pub struct CK_X9_42_MQV_DERIVE_PARAMS {
    pub kdf: CK_X9_42_DH_KDF_TYPE,
    pub ulOtherInfoLen: CK_ULONG,
    pub pOtherInfo: *const CK_BYTE,
    pub ulPublicDataLen: CK_ULONG,
    pub pPublicData: *const CK_BYTE,
    pub ulPrivateDataLen: CK_ULONG,
    pub hPrivateData: CK_OBJECT_HANDLE,
    pub ulPublicDataLen2: CK_ULONG,
    pub pPublicData2: *const CK_BYTE,
    pub publicKey: CK_OBJECT_HANDLE,
}

#[repr(C)]
pub struct CK_KEA_DERIVE_PARAMS {
    pub isSender: CK_BBOOL,
    pub ulRandomLen: CK_ULONG,
    pub pRandomA: *const CK_BYTE,
    pub pRandomB: *const CK_BYTE,
    pub ulPublicDataLen: CK_ULONG,
    pub pPublicData: *const CK_BYTE,
}

/// The parameters to the `CKM_RC2_ECB` and `CKM_RC2_MAC` mechanisms.
///
/// An instance of `CK_RC2_PARAMS` just holds the effective keysize
pub type CK_RC2_PARAMS = CK_ULONG;

/// The parameters to the `CKM_RC2_CBC` mechanism.
#[repr(C)]
pub struct CK_RC2_CBC_PARAMS {
    /// effective bits (1-1024)
    pub ulEffectiveBits: CK_ULONG,
    
    /// IV for CBC mode
    pub iv: [CK_BYTE; 8],
}

/// The parameters for the `CKM_RC2_MAC_GENERAL` mechanism.
#[repr(C)]
pub struct CK_RC2_MAC_GENERAL_PARAMS {
    /// effective bits (1-1024)
    pub ulEffectiveBits: CK_ULONG,

    /// Length of MAC in bytes
    pub ulMacLength: CK_ULONG,
}

/// The parameters to the `CKM_RC5_ECB` and `CKM_RC5_MAC` mechanisms.
#[repr(C)]
pub struct CK_RC5_PARAMS {
    /// wordsize in bits
    pub ulWordsize: CK_ULONG,

    /// number of rounds
    pub ulRounds: CK_ULONG,
}

/// The parameters to the `CKM_RC5_CBC` mechanism.
#[repr(C)]
pub struct CK_RC5_CBC_PARAMS {
    /// wordsize in bits
    pub ulWordsize: CK_ULONG,

    /// number of rounds
    pub ulRounds: CK_ULONG,

    /// pointer to IV
    pub pIv: *const CK_BYTE,

    /// length of IV in bytes
    pub ulIvLen: CK_ULONG,
}

/// The parameters for the `CKM_RC5_MAC_GENERAL` mechanism.
#[repr(C)]
pub struct CK_RC5_MAC_GENERAL_PARAMS {
    /// wordsize in bits
    pub ulWordsize: CK_ULONG,

    /// number of rounds
    pub ulRounds: CK_ULONG,

    /// Length of MAC in bytes
    pub ulMacLength: CK_ULONG,
}

/// The parameters to most block ciphers' `MAC_GENERAL` mechanisms.
///
/// Its value is the length of the MAC
pub type CK_MAC_GENERAL_PARAMS = CK_ULONG;

#[repr(C)]
pub struct CK_DES_CBC_ENCRYPT_DATA_PARAMS {
    pub iv: [CK_BYTE; 8],
    pub pData: *const CK_BYTE,
    pub length: CK_ULONG
}

#[repr(C)]
pub struct CK_AES_CBC_ENCRYPT_DATA_PARAMS {
    pub iv: [CK_BYTE; 16],
    pub pData: *const CK_BYTE,
    pub length: CK_ULONG,
}

/// The parameters to the `CKM_SKIPJACK_PRIVATE_WRAP` mechanism.
#[repr(C)]
pub struct CK_SKIPJACK_PRIVATE_WRAP_PARAMS {
    pub ulPasswordLen: CK_ULONG,
    pub pPassword: *const CK_BYTE,
    pub ulPublicDataLen: CK_ULONG,
    pub pPublicData: *const CK_BYTE,
    pub ulPAndGLen: CK_ULONG,
    pub ulQLen: CK_ULONG,
    pub ulRandomLen: CK_ULONG,
    pub pRandomA: *const CK_BYTE,
    pub pPrimeP: *const CK_BYTE,
    pub pBaseG: *const CK_BYTE,
    pub pSubprimeQ: *const CK_BYTE
}

/// The parameters to the `CKM_SKIPJACK_RELAYX` mechanism.
#[repr(C)]
pub struct CK_SKIPJACK_RELAYX_PARAMS {
    pub ulOldWrappedXLen: CK_ULONG,
    pub pOldWrappedX: *const CK_BYTE,
    pub ulOldPasswordLen: CK_ULONG,
    pub pOldPassword: *const CK_BYTE,
    pub ulOldPublicDataLen: CK_ULONG,
    pub pOldPublicData: *const CK_BYTE,
    pub ulOldRandomLen: CK_ULONG,
    pub pOldRandomA: *const CK_BYTE,
    pub ulNewPasswordLen: CK_ULONG,
    pub pNewPassword: *const CK_BYTE,
    pub ulNewPublicDataLen: CK_ULONG,
    pub pNewPublicData: *const CK_BYTE,
    pub ulNewRandomLen: CK_ULONG,
    pub pNewRandomA: *const CK_BYTE
}

#[repr(C)]
pub struct CK_PBE_PARAMS {
    pub pInitVector: *const CK_BYTE,
    pub pPassword: *const CK_UTF8CHAR,
    pub ulPasswordLen: CK_ULONG,
    pub pSalt: *const CK_BYTE,
    pub ulSaltLen: CK_ULONG,
    pub ilIteraton: CK_ULONG
}

/// The parameters to the CKM_KEY_WRAP_SET_OAEP mechanism.
#[repr(C)]
pub struct CK_KEY_WRAP_SET_OAEP_PARAMS {
    pub bBC: CK_BYTE,
    pub pX: *const CK_BYTE,
    pub ulXLen: CK_ULONG,
}

#[repr(C)]
pub struct CK_SSL3_RANDOM_DATA {
    pub pClientRandom: *const CK_BYTE,
    pub ulClientRandomLen: CK_ULONG,
    pub pServerRandom: *const CK_BYTE,
    pub ulServerRandomLen: CK_ULONG,
}

#[repr(C)]
pub struct CK_SSL3_MASTER_KEY_DERIVE_PARAMS {
    pub RandomInfo: CK_SSL3_RANDOM_DATA,
    pub pVersion: *const CK_VERSION,
}

#[repr(C)]
pub struct CK_SSL3_KEY_MAT_OUT {
    pub hClientMacSecret: CK_OBJECT_HANDLE,
    pub hServerMacSecret: CK_OBJECT_HANDLE,
    pub hClientKey: CK_OBJECT_HANDLE,
    pub hServerKey: CK_OBJECT_HANDLE,
    pub pIVClient: *const CK_BYTE,
    pub pIVServer: *const CK_BYTE,
}

#[repr(C)]
pub struct CK_SSL3_KEY_MAT_PARAMS {
    pub ulMacSizeInBits: CK_ULONG,
    pub ulKeySizeInBits: CK_ULONG,
    pub ulIVSizeInBits: CK_ULONG,
    pub bIsExport: CK_BBOOL,
    pub RandomInfo: CK_SSL3_RANDOM_DATA,
    pub pReturnedKeyMaterial: *const CK_SSL3_KEY_MAT_OUT,
}

#[repr(C)]
pub struct CK_TLS_PRF_PARAMS {
    pub pSeed: *const CK_BYTE,
    pub ulSeedLen: CK_ULONG,
    pub pLabel: *const CK_BYTE,
    pub ulLabelLen: CK_ULONG,
    pub pOutput: *mut CK_BYTE,
    pub pulOutputLen: *mut CK_ULONG,
}

#[repr(C)]
pub struct CK_WTLS_RANDOM_DATA {
    pub pClientRandom: *const CK_BYTE,
    pub ulClientRandomLen: CK_ULONG,
    pub pServerRandom: *const CK_BYTE,
    pub ulServerRandomLen: CK_ULONG,
}

#[repr(C)]
pub struct CK_WTLS_MASTER_KEY_DERIVE_PARAMS {
    pub DigestMechanism: CK_MECHANISM_TYPE,
    pub RandomInfo: CK_WTLS_RANDOM_DATA,
    pub pVersion: *const CK_BYTE
}

#[repr(C)]
pub struct CK_WTLS_PRF_PARAMS {
    pub DigestMechanism: CK_MECHANISM_TYPE,
    pub pSeed: *const CK_BYTE,
    pub ulSeedLen: CK_ULONG,
    pub pLabel: *const CK_BYTE,
    pub ulLabelLen: CK_ULONG,
    pub pOutput: *mut CK_BYTE,
    pub pulOutputLen: *mut CK_ULONG,
}

#[repr(C)]
pub struct CK_WTLS_KEY_MAT_OUT {
    pub hMacSecret: CK_OBJECT_HANDLE,
    pub hKey: CK_OBJECT_HANDLE,
    pub pIV: *const CK_BYTE,
}

#[repr(C)]
pub struct CK_WTLS_KEY_MAT_PARAMS {
    pub DigestMechanism: CK_MECHANISM_TYPE,
    pub ulMacSizeInBits: CK_ULONG,
    pub ulKeySizeInBits: CK_ULONG,
    pub ulIVSizeInBits: CK_ULONG,
    pub ulSequenceNumber: CK_ULONG,
    pub bIsExport: CK_BBOOL,
    pub RandomInfo: CK_WTLS_RANDOM_DATA,
    pub pReturnedKeyMaterial: *mut CK_WTLS_KEY_MAT_OUT,
}

#[repr(C)]
pub struct CK_CMS_SIG_PARAMS {
    pub certificateHandle: CK_OBJECT_HANDLE,
    pub pSigningMechanism: *const CK_MECHANISM,
    pub pDigestMechanism: *const CK_MECHANISM,
    pub pContentType: *const CK_UTF8CHAR,
    pub pRequestedAttributes: *const CK_BYTE,
    pub ulRequestedAttributes: CK_ULONG,
    pub pRequiredAttributes: *const CK_BYTE,
    pub ulRequiredAttributesLen: CK_ULONG,
}

#[repr(C)]
pub struct CK_KEY_DERIVATION_STRING_DATA {
    pub pData: *const CK_BYTE,
    pub ulLen: CK_ULONG,
}

/// Used for the CKM_EXTRACT_KEY_FROM_KEY mechanism.
///
/// It specifies which bit of the base key should be used as the first bit
/// of the derived key.
pub type CK_EXTRACT_PARAMS = CK_ULONG;

/// Indicates the Pseudo-Random Function (PRF) used to generate key
/// bits using PKCS #5 PBKDF2.
pub type CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE = CK_ULONG;

pub const CKP_PKCS5_PBKD2_HMAC_SHA1:
            CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE = 0x00000001;
pub const CKP_PKCS5_PBKD2_HMAC_GOSTR3411:
            CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE = 0x00000002;
pub const CKP_PKCS5_PBKD2_HMAC_SHA224:
            CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE = 0x00000003;
pub const CKP_PKCS5_PBKD2_HMAC_SHA256:
            CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE = 0x00000004;
pub const CKP_PKCS5_PBKD2_HMAC_SHA384:
            CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE = 0x00000005;
pub const CKP_PKCS5_PBKD2_HMAC_SHA512:
            CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE = 0x00000006;
pub const CKP_PKCS5_PBKD2_HMAC_SHA512_224:
            CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE = 0x00000007;
pub const CKP_PKCS5_PBKD2_HMAC_SHA512_256:
            CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE = 0x00000008;

/// Indicates the source of the salt value when deriving a key using PKCS #5
/// PBKDF2.
pub type CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE = CK_ULONG;

pub const CKZ_SALT_SPECIFIED: CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE = 0x00000001;

/// Provides the parameters to the CKM_PKCS5_PBKD2 mechanism.
#[repr(C)]
pub struct CK_PKCS5_PBKD2_PARAMS {
    pub saltSource: CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE,
    pub pSaltSourceData: *const CK_VOID,
    pub ulSaltSourceDataLen: CK_ULONG,
    pub iterations: CK_ULONG,
    pub prf: CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE,
    pub pPrfData: *const CK_VOID,
    pub ulPrfDataLen: CK_ULONG,
    pub pPassword: *const CK_UTF8CHAR,
    pub ulPasswordLen: *const CK_ULONG,
}

/// The corrected version of `CK_PKCS5_PBKD2_PARAMS`.
///
/// Provides the parameters to the CKM_PKCS5_PBKD2 mechanism noting that the
/// `ulPasswordLen` field is an integer value, not a pointer.
#[repr(C)]
pub struct CK_PKCS5_PBKD2_PARAMS2 {
    pub saltSource: CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE,
    pub pSaltSourceData: *const CK_VOID,
    pub ulSaltSourceDataLen: CK_ULONG,
    pub iterations: CK_ULONG,
    pub prf: CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE,
    pub pPrfData: *const CK_VOID,
    pub ulPrfDataLen: CK_ULONG,
    pub pPassword: *const CK_UTF8CHAR,
    pub ulPasswordLen: CK_ULONG,
}

pub type CK_OTP_PARAM_TYPE = CK_ULONG;
pub type CK_PARAM_TYPE = CK_OTP_PARAM_TYPE;

#[repr(C)]
pub struct CK_OTP_PARAM {
    pub paramType: CK_OTP_PARAM_TYPE,
    pub pValue: *const CK_VOID,
    pub ulValueLen: CK_ULONG
}

#[repr(C)]
pub struct CK_OTP_PARAMS {
    pub pParams: *const CK_OTP_PARAM,
    pub ulCount: CK_ULONG
}

#[repr(C)]
pub struct CK_OTP_SIGNATURE_INFO {
    pub pParams: *const CK_OTP_PARAM,
    pub ulCount: CK_ULONG,
}

pub const CK_OTP_VALUE        : CK_OTP_PARAM_TYPE =  0;
pub const CK_OTP_PIN          : CK_OTP_PARAM_TYPE =  1;
pub const CK_OTP_CHALLENGE    : CK_OTP_PARAM_TYPE =  2;
pub const CK_OTP_TIME         : CK_OTP_PARAM_TYPE =  3;
pub const CK_OTP_COUNTER      : CK_OTP_PARAM_TYPE =  4;
pub const CK_OTP_FLAGS        : CK_OTP_PARAM_TYPE =  5;
pub const CK_OTP_OUTPUT_LENGTH: CK_OTP_PARAM_TYPE =  6;
pub const CK_OTP_OUTPUT_FORMAT: CK_OTP_PARAM_TYPE =  7;

pub const CKF_NEXT_OTP          : CK_FLAGS = 0x00000001;
pub const CKF_EXCLUDE_TIME      : CK_FLAGS = 0x00000002;
pub const CKF_EXCLUDE_COUNTER   : CK_FLAGS = 0x00000004;
pub const CKF_EXCLUDE_CHALLENGE : CK_FLAGS = 0x00000008;
pub const CKF_EXCLUDE_PIN       : CK_FLAGS = 0x00000010;
pub const CKF_USER_FRIENDLY_OTP : CK_FLAGS = 0x00000020;

#[repr(C)]
pub struct CK_KIP_PARAMS {
    pub pMechanism: *const CK_MECHANISM,
    pub hKey: CK_OBJECT_HANDLE,
    pub pSee: *const CK_BYTE,
    pub ulSeedLen: CK_ULONG,
}

#[repr(C)]
pub struct CK_AES_CTR_PARAMS {
    pub ulCounterBits: CK_ULONG,
    pub cb: [CK_BYTE; 16],
}

#[repr(C)]
pub struct CK_GCM_PARAMS {
    pub pIv: *const CK_BYTE,
    pub ulIvLen: CK_ULONG,
    pub ulIvBits: CK_ULONG,
    pub pAAD: *const CK_BYTE,
    pub ulAADLen: CK_ULONG,
    pub ulTagBit: CK_ULONG,
}

#[repr(C)]
pub struct CK_CCM_PARAMS {
    pub ulDataLen: CK_ULONG,
    pub pNonce: *const CK_BYTE,
    pub ulNonceLen: CK_ULONG,
    pub pAAD: *const CK_BYTE,
    pub ulAADLen: CK_ULONG,
    pub ilMACLen: CK_ULONG,
}

/// Deprecated: Use `CK_GCM_PARAMS`.
#[repr(C)]
pub struct CK_AES_GCM_PARAMS {
    pub pIv: *const CK_BYTE,
    pub ulIvLen: CK_ULONG,
    pub ulIvBits: CK_ULONG,
    pub pAAD: *const CK_BYTE,
    pub ulAADLen: CK_ULONG,
    pub ulTagBits: CK_ULONG,
}

/// Deprecated: Use `CK_CCM_PARAMS`.
#[repr(C)]
pub struct CK_AES_CCM_PARAMS {
    pub ulDataLen: CK_ULONG,
    pub pNonce: *const CK_BYTE,
    pub ulNonceLen: CK_ULONG,
    pub pAAD: *const CK_BYTE,
    pub ulAADLen: CK_ULONG,
    pub ulMACLen: CK_ULONG,
}

#[repr(C)]
pub struct CK_CAMELLIA_CTR_PARAMS {
    pub ulCounterBits: CK_ULONG,
    pub cb: [CK_BYTE; 16],
}

#[repr(C)]
pub struct CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS {
    pub iv: [CK_BYTE; 16],
    pub pData: *const CK_BYTE,
    pub length: CK_ULONG,
}

#[repr(C)]
pub struct CK_ARIA_CBC_ENCRYPT_DATA_PARAMS {
    pub iv: [CK_BYTE; 16],
    pub pData: *const CK_BYTE,
    pub length: CK_ULONG,
}

#[repr(C)]
pub struct CK_DSA_PARAMETER_GEN_PARAM {
    pub hash: CK_MECHANISM_TYPE,
    pub pSeed: *const CK_BYTE,
    pub ulSeedLen: CK_ULONG,
    pub ulIndex: CK_ULONG,
}

#[repr(C)]
pub struct CK_ECDH_AES_KEY_WRAP_PARAMS {
    pub ulAESKeyBits: CK_ULONG,
    pub kdf: CK_EC_KDF_TYPE,
    pub ulSharedDataLen: CK_ULONG,
    pub pSharedData: *const CK_BYTE,
}

pub type CK_JAVA_MIDP_SECURITY_DOMAIN = CK_ULONG;

#[repr(C)]
pub struct CK_RSA_AES_KEY_WRAP_PARAMS {
    pub ulAESKeyBits: CK_ULONG,
    pub pOAEPParams: *const CK_RSA_PKCS_OAEP_PARAMS,
}

#[repr(C)]
pub struct CK_TLS12_MASTER_KEY_DERIVE_PARAMS {
    pub RandomInfo: CK_SSL3_RANDOM_DATA,
    pub pVersion: *const CK_VERSION,
    pub prfHashMechanism: CK_MECHANISM_TYPE,
}

#[repr(C)]
pub struct CK_TLS12_KEY_MAT_PARAMS {
    pub ulMacSizeInBits: CK_ULONG,
    pub ulKeySizeInBits: CK_ULONG,
    pub ulIVSizeInBits: CK_ULONG,
    pub bIsExport: CK_BBOOL,
    pub RandomInfo: CK_SSL3_RANDOM_DATA,
    pub pReturnedKeyMaterial: *const CK_SSL3_KEY_MAT_OUT,
    pub prfHashMechanism: CK_MECHANISM_TYPE,
}

#[repr(C)]
pub struct CK_TLS_KDF_PARAMS {
    pub prfMechanism: CK_MECHANISM_TYPE,
    pub pLabel: *const CK_BYTE,
    pub ulLabelLength: CK_ULONG,
    pub RandomInfo: CK_SSL3_RANDOM_DATA,
    pub pContextData: *const CK_BYTE,
    pub ulContextDataLength: CK_ULONG
}

#[repr(C)]
pub struct CK_TLS_MAC_PARAMS {
    pub prfHashMechanism: CK_MECHANISM_TYPE,
    pub ulMacLength: CK_ULONG,
    pub ulServerOrClient: CK_ULONG
}

#[repr(C)]
pub struct CK_GOSTR3410_DERIVE_PARAMS {
    pub kdf: CK_EC_KDF_TYPE,
    pub pPublicData: *const CK_BYTE,
    pub ulPublicDataLen: CK_ULONG,
    pub pUKM: *const CK_BYTE,
    pub ulUKMLen: CK_ULONG,
}

#[repr(C)]
pub struct CK_GOSTR3410_KEY_WRAP_PARAMS {
    pub pWrapOID: *const CK_BYTE,
    pub ulWrapOIDLen: CK_ULONG,
    pub pUKM: *const CK_BYTE,
    pub ulUKMLen: CK_ULONG,
    pub hKey: CK_OBJECT_HANDLE,
}

#[repr(C)]
pub struct CK_SEED_CBC_ENCRYPT_DATA_PARAMS {
    pub iv: [CK_BYTE; 16],
    pub pData: *const CK_BYTE,
    pub length: CK_ULONG,
}


//------------ pkcs11f.h ----------------------------------------------------
//
// There’s three things defined via this header: A type for the function,
// an extern function definition, and an entry into the CK_FUNCTION_LIST
// structure. We can (almost) achieve the same thing with macros.

macro_rules! pkcs11_functions {
    {
        $(
            $(#[$attr:meta])*
            CK_PKCS11_FUNCTION_INFO($func:ident, $ftype:ident)(
                $( $arg:ident: $argty:ty ),*
            );
        )*
    } => {
        // Function type. 
        $(
            pub type $ftype = unsafe extern "C" fn ( $( $arg: $argty ),* )
                                                    -> CK_RV;
        )*

        // Extern
        extern "C" {
            $(
                $( #[$attr] )*
                pub fn $func( $( $arg: $argty ),*) -> CK_RV;
            )*
        }

        // CK_FUNCTION_LIST
        #[repr(C)]
        pub struct CK_FUNCTION_LIST {
            pub version: CK_VERSION,

            $(
                pub $func: $ftype,
            )*
        }
    }
}


pkcs11_functions!{
    /// Initializes the Cryptoki library.
    ///
    /// If the `pInitArgs` argument is not a null pointer, it gets cast
    /// to `*const CK_C_INITIALIZE_ARGS` and dereferenced.
    CK_PKCS11_FUNCTION_INFO(C_Initialize, CK_C_Initialize)(
        pInitArgs: *const CK_VOID
    );

    /// Indicates that an application is done with the Cryptoki library.
    ///
    /// The reserved argument should be a null pointer.
    CK_PKCS11_FUNCTION_INFO(C_Finalize, CK_C_Finalize)(
        pReserved: *const CK_VOID
    );

    /// Returns general information about Cryptoki.
    CK_PKCS11_FUNCTION_INFO(C_GetInfo, CK_C_GetInfo)(
        pInfo: *mut CK_INFO
    );

    /// Returns the function list.
    CK_PKCS11_FUNCTION_INFO(C_GetFunctionList, CK_C_GetFunctionList)(
        ppFunctionList: *mut *const CK_FUNCTION_LIST
    );

    //--- Slot and token management

    /// Obtains a list of slots in the system.
    CK_PKCS11_FUNCTION_INFO(C_GetSlotList, CK_C_GetSlotList)(
        tokenPresent: CK_BBOOL,
        pSlotList: *mut CK_SLOT_ID,
        pulCount: *mut CK_ULONG
    );

    /// Obtains information about a particular slot in the system.
    CK_PKCS11_FUNCTION_INFO(C_GetSlotInfo, CK_C_GetSlotInfo)(
        slotID: CK_SLOT_ID,
        pInfo: *mut CK_SLOT_INFO
    );

    /// Obtains information about a particular token in the system.
    CK_PKCS11_FUNCTION_INFO(C_GetTokenInfo, CK_C_GetTokenInfo)(
        slotID: CK_SLOT_ID,
        pInfo: *mut CK_TOKEN_INFO
    );

    /// Obtains a list of mechanism types supported by a token.
    CK_PKCS11_FUNCTION_INFO(C_GetMechanismList, CK_C_GetMechanismList)(
        slotID: CK_SLOT_ID,
        pMechanismList: *mut CK_MECHANISM_TYPE,
        pulCount: *mut CK_ULONG
    );

    /// Obtains information about a mechanism possibly supported by a token.
    CK_PKCS11_FUNCTION_INFO(C_GetMechanismInfo, CK_C_GetMechanismInfo)(
        slotID: CK_SLOT_ID,
        mechanismType: CK_MECHANISM_TYPE,
        pInfo: *mut CK_MECHANISM_INFO
    );

    /// Initializes a token.
    CK_PKCS11_FUNCTION_INFO(C_InitToken, CK_C_InitToken)(
        slotID: CK_SLOT_ID,
        pPin: *const CK_UTF8CHAR,
        ulPinLin: CK_ULONG,
        pLabel: *const CK_UTF8CHAR
    );

    /// Initializes the normal user's PIN.
    CK_PKCS11_FUNCTION_INFO(C_InitPIN, CK_C_InitPIN)(
        hSession: CK_SESSION_HANDLE,
        pPin: *const CK_UTF8CHAR,
        ulPinLen: CK_ULONG
    );

    /// Modifies the PIN of the user who is logged in.
    CK_PKCS11_FUNCTION_INFO(C_SetPIN, CK_C_SetPIN)(
        hSession: CK_SESSION_HANDLE,
        pOldPin: *const CK_UTF8CHAR,
        ulOldPinLen: CK_ULONG,
        pNewPin: *const CK_UTF8CHAR,
        ulNewPinLen: CK_ULONG
    );


    //--- Session Management

    /// Opens a session between an application and a token.
    CK_PKCS11_FUNCTION_INFO(C_OpenSession, CK_C_OpenSession)(
        slotID: CK_SLOT_ID,
        flags: CK_FLAGS,
        pApplication: *const CK_VOID,
        Notify: CK_NOTIFY,
        phSession: *mut CK_SESSION_HANDLE
    );

    /// Closes a session between an application and a token.
    CK_PKCS11_FUNCTION_INFO(C_CloseSession, CK_C_CloseSession)(
        hSession: CK_SESSION_HANDLE
    );

    /// Closes all sessions with a token.
    CK_PKCS11_FUNCTION_INFO(C_CloseAllSessions, CK_C_CloseAllSessions)(
        slotID: CK_SLOT_ID
    );

    /// Obtains information about the session.
    CK_PKCS11_FUNCTION_INFO(C_GetSessionInfo, CK_C_GetSessionInfo)(
        hSession: CK_SESSION_HANDLE,
        pInfo: *mut CK_SESSION_INFO
    );

    /// Obtains the state of the cryptographic operation in a session.
    CK_PKCS11_FUNCTION_INFO(C_GetOperationState, CK_C_GetOperationState)(
        hSession: CK_SESSION_HANDLE,
        pOperationState: *mut CK_BYTE,
        pulOperationStateLen: *mut CK_ULONG
    );

    /// Restores the state of the cryptographic operation in a session.
    CK_PKCS11_FUNCTION_INFO(C_SetOperationState, CK_C_SetOperationState)(
        hSession: CK_SESSION_HANDLE,
        pOperationState: *const CK_BYTE,
        ulOperationStateLen: CK_ULONG,
        hEncryptionKey: CK_OBJECT_HANDLE,
        hAuthenticationKey: CK_OBJECT_HANDLE
    );

    /// Logs a user into a token.
    CK_PKCS11_FUNCTION_INFO(C_Login, CK_C_Login)(
        hSession: CK_SESSION_HANDLE,
        userType: CK_USER_TYPE,
        pPin: *const CK_UTF8CHAR,
        ulPinLen: CK_ULONG
    );

    /// Logs a user out from a token.
    CK_PKCS11_FUNCTION_INFO(C_Logout, CK_C_Logout)(
        hSession: CK_SESSION_HANDLE
    );


    //--- Object Management

    /// Creates a new object.
    CK_PKCS11_FUNCTION_INFO(C_CreateObject, CK_C_CreateObject)(
        hSession: CK_SESSION_HANDLE,
        pTemplate: *const CK_ATTRIBUTE,
        ulCount: CK_ULONG,
        phObject: *mut CK_OBJECT_HANDLE
    );

    /// Copies an object, creating a new object for the copy.
    CK_PKCS11_FUNCTION_INFO(C_CopyObject, CK_C_CopyObject)(
        hSession: CK_SESSION_HANDLE,
        hObject: CK_OBJECT_HANDLE,
        pTemplate: *const CK_ATTRIBUTE,
        ulCount: CK_ULONG,
        phNewObject: *mut CK_OBJECT_HANDLE
    );

    /// Destroys an object.
    CK_PKCS11_FUNCTION_INFO(C_DestroyObject, CK_C_DestroyObject)(
        hSession: CK_SESSION_HANDLE,
        hObject: CK_OBJECT_HANDLE
    );

    /// Gets the size of an object in bytes.
    CK_PKCS11_FUNCTION_INFO(C_GetObjectSize, CK_C_GetObjectSize)(
        hSession: CK_SESSION_HANDLE,
        hObject: CK_OBJECT_HANDLE,
        pulSize: *mut CK_ULONG
    );

    /// Obtains the value of one or more object attributes.
    CK_PKCS11_FUNCTION_INFO(C_GetAttributeValue, CK_C_GetAttributeValue)(
        hSession: CK_SESSION_HANDLE,
        hObject: CK_OBJECT_HANDLE,
        pTemplate: *mut CK_ATTRIBUTE,
        ulCount: CK_ULONG
    );

    /// Modifies the value of one or more object attributes. 
    CK_PKCS11_FUNCTION_INFO(C_SetAttributeValue, CK_C_SetAttributeValue)(
        hSession: CK_SESSION_HANDLE,
        hObject: CK_OBJECT_HANDLE,
        pTemplate: *const CK_ATTRIBUTE,
        ulCount: CK_ULONG
    );

    /// Initializes a search for token and session objects matching a template.
    CK_PKCS11_FUNCTION_INFO(C_FindObjectsInit, C_FindObjectsInit)(
        hSession: CK_SESSION_HANDLE,
        pTemplate: *const CK_ATTRIBUTE,
        ulCount: CK_ULONG
    );

    /// Continues a search for token and session objects matching a template.
    ///
    /// Obtains additional object handles.
    CK_PKCS11_FUNCTION_INFO(C_FindObjects, CK_C_FindObjects)(
        hSession: CK_SESSION_HANDLE,
        phObject: *mut CK_OBJECT_HANDLE,
        ulMaxObjectCount: CK_ULONG,
        pulObjectCount: *mut CK_ULONG
    );

    /// Finishes a search for token and session objects.
    CK_PKCS11_FUNCTION_INFO(C_FindObjectsFinal, CK_C_FindObjectsFinal)(
        hSession: CK_SESSION_HANDLE
    );


    //--- Encryption and Decryption

    /// Initializes an encryption operation.
    CK_PKCS11_FUNCTION_INFO(C_EncryptInit, CK_C_EncryptInit)(
        hSession: CK_SESSION_HANDLE,
        pMechanism: *const CK_MECHANISM,
        hKey: CK_OBJECT_HANDLE
    );

    /// Encrypts single-part data.
    CK_PKCS11_FUNCTION_INFO(C_Encrypt, CK_C_Encrypt)(
        hSession: CK_SESSION_HANDLE,
        pData: *const CK_BYTE,
        ulDataLen: CK_ULONG,
        pEncryptedData: *mut CK_BYTE,
        ulEncryptedDataLen: *mut CK_ULONG
    );

    /// Continues a multiple-part encryption operation.
    CK_PKCS11_FUNCTION_INFO(C_EncryptUpdate, CK_C_EncryptUpdate)(
        hSession: CK_SESSION_HANDLE,
        pPart: *const CK_BYTE,
        ulPartLen: CK_ULONG,
        pEncryptedPart: *mut CK_BYTE,
        ulEncryptedPartLen: *mut CK_ULONG
    );

    /// Finishes a multiple-part encryption operation.
    CK_PKCS11_FUNCTION_INFO(C_EncryptFinal, CK_C_EncryptFinal)(
        hSession: CK_SESSION_HANDLE,
        pLastEncryptedPart: *mut CK_BYTE,
        ulLastEncryptedPartLen: *mut CK_ULONG
    );

    /// Initializes a decryption operation.
    CK_PKCS11_FUNCTION_INFO(C_DecryptInit, CK_C_DecryptInit)(
        hSession: CK_SESSION_HANDLE,
        pMechanism: *const CK_MECHANISM,
        hKey: CK_OBJECT_HANDLE
    );

    /// Decrypts encrypted data in a single part.
    CK_PKCS11_FUNCTION_INFO(C_Decrypt, CK_C_Decrypt)(
        hSession: CK_SESSION_HANDLE,
        pEncryptedData: *const CK_BYTE,
        ulEncryptedDataLen: CK_ULONG,
        pData: *mut CK_BYTE,
        ulDataLen: *mut CK_ULONG
    );

    /// Continues a multiple-part decryption operation.
    CK_PKCS11_FUNCTION_INFO(C_DecryptUpdate, CK_C_DecryptUpdate)(
        hSession: CK_SESSION_HANDLE,
        pEncryptedPart: *const CK_BYTE,
        ulEncryptedPartLen: CK_ULONG,
        pPart: *mut CK_BYTE,
        ulPartLen: *mut CK_ULONG
    );

    /// Finishes a multiple-part decryption operation.
    CK_PKCS11_FUNCTION_INFO(C_DecryptFinal, CK_C_DecryptFinal)(
        hSession: CK_SESSION_HANDLE,
        pLastPart: *mut CK_BYTE,
        ulLastPartLen: *mut CK_ULONG
    );


    //--- Message Digesting

    /// Initializes a message-digesting operation.
    CK_PKCS11_FUNCTION_INFO(C_DigestInit, CK_C_DigestInit)(
        hSession: CK_SESSION_HANDLE,
        pMechanism: *const CK_MECHANISM
    );

    /// Digests data in a single part.
    CK_PKCS11_FUNCTION_INFO(C_Digest, CK_C_Digest)(
        hSession: CK_SESSION_HANDLE,
        pData: *const CK_BYTE,
        ulDataLen: CK_ULONG,
        pDigest: *mut CK_BYTE,
        ulDigestLen: *mut CK_ULONG
    );

    /// Continues a multiple-part message-digesting operation.
    CK_PKCS11_FUNCTION_INFO(C_DigestUpdate, CK_C_DigestUpdate)(
        hSession: CK_SESSION_HANDLE,
        pPart: *const CK_BYTE,
        ulPartLen: CK_ULONG
    );

    /// Continues a multi-part message-digesting operation.
    ///
    /// Digests the value of a secret key as part of the data already digested.
    CK_PKCS11_FUNCTION_INFO(C_DigestKey, CK_C_DigestKey)(
        hSession: CK_SESSION_HANDLE,
        hKey: CK_OBJECT_HANDLE
    );

    /// Finishes a multiple-part message-digesting operation.
    CK_PKCS11_FUNCTION_INFO(C_DigestFinal, CK_C_DigestFinal)(
        hSession: CK_SESSION_HANDLE,
        pDigest: *mut CK_BYTE,
        ulDigestLen: *mut CK_ULONG
    );


    //--- Signing and MACing

    /// Initializes a signature (private key encryption) operation.
    ///
    /// The signature is (will be) an appendix to the data, and plaintext
    /// cannot be recovered from the signature.
    CK_PKCS11_FUNCTION_INFO(C_SignInit, CK_C_SignInit)(
        hSession: CK_SESSION_HANDLE,
        pMechanism: *const CK_MECHANISM,
        hkey: CK_OBJECT_HANDLE
    );

    /// Signs (encrypts with private key) data in a single part.
    ///
    /// The signature is (will be) an appendix to the data, and plaintext
    /// cannot be recovered from the signature.
    CK_PKCS11_FUNCTION_INFO(C_Sign, CK_C_Sign)(
        hSession: CK_SESSION_HANDLE,
        pData: *const CK_BYTE,
        ulDataLen: CK_ULONG,
        pSignature: *mut CK_BYTE,
        pulSignatureLen: *mut CK_ULONG
    );

    /// Continues a multiple-part signature operation.
    ///
    /// The signature is (will be) an appendix to the data, and plaintext
    /// cannot be recovered from the signature.
    CK_PKCS11_FUNCTION_INFO(C_SignUpdate, CK_C_SignUpdate)(
        hSession: CK_SESSION_HANDLE,
        pPart: *const CK_BYTE,
        ulPartLen: CK_ULONG
    );

    /// Finishes a multiple-part signature operation, returning the signature.
    CK_PKCS11_FUNCTION_INFO(C_SignFinal, CK_C_SignFinal)(
        hSession: CK_SESSION_HANDLE,
        pSignature: *mut CK_BYTE,
        ulSignatureLen: *mut CK_ULONG
    );

    /// Initializes a signature operation.
    ///
    /// The data can be recovered from the signature.
    CK_PKCS11_FUNCTION_INFO(C_SignRecoverInit, CK_C_SignRecoverInit)(
        hSession: CK_SESSION_HANDLE,
        pMechanism: *const CK_MECHANISM,
        hkey: CK_OBJECT_HANDLE
    );

    /// Signs data in a single operation.
    ///
    /// The data can be recovered from the signature.
    CK_PKCS11_FUNCTION_INFO(C_SignRecover, CK_C_SignRecover)(
        hSession: CK_SESSION_HANDLE,
        pData: *const CK_BYTE,
        ulDataLen: CK_ULONG,
        pSignature: *mut CK_BYTE,
        pulSignatureLen: *mut CK_ULONG
    );


    //--- Verifying signatures and MACs.

    /// Initializes a verification operation.
    ///
    /// The signature is an appendix to the data, and plaintext cannot be
    /// recovered from the signature (e.g. DSA).
    CK_PKCS11_FUNCTION_INFO(C_VerifyInit, CK_C_VerifyInit)(
        hSession: CK_SESSION_HANDLE,
        pMechanism: *const CK_MECHANISM,
        hkey: CK_OBJECT_HANDLE
    );

    /// Verifies a signature in a single-part operation.
    ///
    /// The signature is an appendix to the data, and plaintext cannot be
    /// recovered from the signature.
    CK_PKCS11_FUNCTION_INFO(C_Verify, CK_C_Verify)(
        hSession: CK_SESSION_HANDLE,
        pData: *const CK_BYTE,
        ulDataLen: CK_ULONG,
        pSignature: *const CK_BYTE,
        ulSignatureLen: CK_ULONG
    );

    /// Continues a multiple-part verification operation.
    ///
    /// The signature is an appendix to the data, and plaintext cannot be
    /// recovered from the signature.
    CK_PKCS11_FUNCTION_INFO(C_VerifyUpdate, CK_C_VerifyUpdate)(
        hSession: CK_SESSION_HANDLE,
        pData: *const CK_BYTE,
        ulDataLen: CK_ULONG
    );

    /// Finishes a multiple-part verification operation, checking the signature
    CK_PKCS11_FUNCTION_INFO(C_VerifyFinal, CK_C_VerifyFinal)(
        hSession: CK_SESSION_HANDLE,
        pSignature: *const CK_BYTE,
        ulSignatureLen: CK_ULONG
    );

    /// Initializes a signature verification operation.
    ///
    /// The data is recovered from the signature.
    CK_PKCS11_FUNCTION_INFO(C_VerifyRecoverInit, CK_C_VerifyRecoverInit)(
        hSession: CK_SESSION_HANDLE,
        pMechanism: *const CK_MECHANISM,
        hkey: CK_OBJECT_HANDLE
    );

    /// Verifies a signature in a single-part operation.
    ///
    /// The data is recovered from the signature.
    CK_PKCS11_FUNCTION_INFO(C_VerifyRecover, CK_C_VerifyRecover)(
        hSession: CK_SESSION_HANDLE,
        pSignature: *const CK_BYTE,
        ulSignatureLen: CK_ULONG,
        pData: *mut CK_BYTE,
        pulDataLen: *mut CK_ULONG
    );


    //--- Dual-function cryptography operations

    /// Continues a multiple-part digesting and encryption operation.
    CK_PKCS11_FUNCTION_INFO(C_DigestEncryptUpdate, CK_C_DigestEncryptUpdate)(
        hSession: CK_SESSION_HANDLE,
        pPart: *const CK_BYTE,
        ulPartLen: CK_ULONG,
        pEncryptedPart: *mut CK_BYTE,
        pulEncryptedPartLen: *mut CK_ULONG
    );

    /// Continues a multiple-part decryption and digesting operation.
    CK_PKCS11_FUNCTION_INFO(C_DecryptDigestUpdate, CK_C_DecryptDigestUpdate)(
        hSession: CK_SESSION_HANDLE,
        pEncryptedData: *const CK_BYTE,
        ulEncryptedDataLen: CK_ULONG,
        pPart: *mut CK_BYTE,
        pulPartLen: *mut CK_ULONG
    );

    /// Continues a multiple-part signing and encryption operation.
    CK_PKCS11_FUNCTION_INFO(C_SignEncryptUpdate, CK_C_SignEncryptUpdate)(
        hSession: CK_SESSION_HANDLE,
        pPart: *const CK_BYTE,
        ulPartLen: CK_ULONG,
        pEncryptedPart: *mut CK_BYTE,
        pulEncryptedPartLen: *mut CK_ULONG
    );

    /// Continues a multiple-part decryption and verify operation.
    CK_PKCS11_FUNCTION_INFO(C_DecryptVerifyUpdate, CK_C_DecryptVerifyUpdate)(
        hSession: CK_SESSION_HANDLE,
        pEncryptedData: *const CK_BYTE,
        ulEncryptedDataLen: CK_ULONG,
        pPart: *mut CK_BYTE,
        pulPartLen: *mut CK_ULONG
    );


    //--- Key Management

    /// Generates a secret key, creating a new key object.
    CK_PKCS11_FUNCTION_INFO(C_GenerateKey, CK_C_GenerateKey)(
        hSession: CK_SESSION_HANDLE,
        pMechanism: *const CK_MECHANISM,
        pTemplate: *const CK_ATTRIBUTE,
        ulCount: CK_ULONG,
        phKey: *mut CK_OBJECT_HANDLE
    );

    /// Generates a public-key/private-key pair, creating new key objects.
    CK_PKCS11_FUNCTION_INFO(C_GenerateKeyPair, CK_C_GenerateKeyPair)(
        hSession: CK_SESSION_HANDLE,
        pMechanism: *const CK_MECHANISM,
        pPublicKeyTemplate: *const CK_ATTRIBUTE,
        ulPublicKeyAttributeCount: CK_ULONG,
        pPrivateKeyTemplate: *const CK_ATTRIBUTE,
        ulPrivateKeyAttributeCount: CK_ULONG,
        phPublicKey: *mut CK_OBJECT_HANDLE,
        phPrivateKey: *mut CK_OBJECT_HANDLE
    );

    /// Wraps (i.e., encrypts) a key.
    CK_PKCS11_FUNCTION_INFO(C_WrapKey, CK_C_WrapKey)(
        hSession: CK_SESSION_HANDLE,
        pMechanism: *const CK_MECHANISM,
        hWrappingKey: CK_OBJECT_HANDLE,
        hKey: CK_OBJECT_HANDLE,
        pWrappedKey: *mut CK_BYTE,
        pulWrappedkeyLen: *mut CK_ULONG
    );

    /// Unwraps (decrypts) a wrapped key, creating a new key object.
    CK_PKCS11_FUNCTION_INFO(C_UnwrapKey, CK_C_UnwrapKey)(
        hSession: CK_SESSION_HANDLE,
        pMechanism: *const CK_MECHANISM,
        hUnwrappingKey: CK_OBJECT_HANDLE,
        pWrappedKey: *const CK_BYTE,
        ulWrappedKeyLen: CK_ULONG,
        pTemplate: *const CK_ATTRIBUTE,
        ulAttributeCount: CK_ULONG,
        phKey: *mut CK_OBJECT_HANDLE
    );

    /// Derives a key from a base key, creating a new key object.
    CK_PKCS11_FUNCTION_INFO(C_DeriveKey, CK_C_DeriveKey)(
        hSession: CK_SESSION_HANDLE,
        pMechanism: *const CK_MECHANISM,
        hBaseKey: CK_OBJECT_HANDLE,
        pTemplate: *const CK_ATTRIBUTE,
        ulAttributeCount: CK_ULONG,
        phKey: *mut CK_OBJECT_HANDLE
    );


    //--- Random number generation

    /// Mixes additional seed material into the token's random number generator.
    CK_PKCS11_FUNCTION_INFO(C_SeedRandom, CK_C_SeedRandom)(
        hSession: CK_SESSION_HANDLE,
        pSeed: *const CK_BYTE,
        ulSeedLen: CK_ULONG
    );

    /// Generates random data.
    CK_PKCS11_FUNCTION_INFO(C_GenerateRandom, CK_C_GenerateRandom)(
        hSession: CK_SESSION_HANDLE,
        RandomData: *mut CK_BYTE,
        ulRandomLen: CK_ULONG
    );

    
    //--- Parallel Function Management
    
    /// Obtains an updated status of a function running in parallel.
    ///
    /// This is a legacy function.
    CK_PKCS11_FUNCTION_INFO(C_GetFunctionStatus, CK_C_GetFunctionStatus)(
        hSession: CK_SESSION_HANDLE
    );

    /// Cancels a function running in parallel.
    ///
    /// This is a legacy function.
    CK_PKCS11_FUNCTION_INFO(C_CancelFunction, CK_C_CancelFunction)(
        hSession: CK_SESSION_HANDLE
    );

    /// Waits for a slot event (token insertion, removal, etc.) to occur.
    CK_PKCS11_FUNCTION_INFO(C_WaitForSlotEvent, CK_C_WaitForSlotEvent)(
        flags: CK_FLAGS,
        pSlot: *mut CK_SLOT_ID,
        pReserved: *const CK_VOID
    );
}

