
use pkcs11_sys as sys;
use super::to_ck_long;


//------------ Macros for Making Types ---------------------------------------

/// Wrapper for creating all the types.
macro_rules! ck_types {
    (
        $(
            $(#[$attr:meta])*
            type $typename:ident {
                $(
                    $(#[$item_attr:meta])* const $item:ident;
                )*
            }
        )+
    ) => {
        $(
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
        )*

        /// All constants.
        pub mod consts {
           $( 
                $(
                    $(#[$item_attr])*
                    pub const $item: super::$typename
                            = super::$typename(::pkcs11_sys::$item);
                )*
            )*
        }
    }
}

ck_types! {

    //------------ AttributeType ---------------------------------------------

    type AttributeType {
        const CKA_CLASS;
        const CKA_TOKEN;
        const CKA_PRIVATE;
        const CKA_LABEL;
        const CKA_APPLICATION;
        const CKA_VALUE;
        const CKA_OBJECT_ID;
        const CKA_CERTIFICATE_TYPE;
        const CKA_ISSUER;
        const CKA_SERIAL_NUMBER;
        const CKA_AC_ISSUER;
        const CKA_OWNER;
        const CKA_ATTR_TYPES;
        const CKA_TRUSTED;
        const CKA_CERTIFICATE_CATEGORY;
        const CKA_JAVA_MIDP_SECURITY_DOMAIN;
        const CKA_URL;
        const CKA_HASH_OF_SUBJECT_PUBLIC_KEY;
        const CKA_HASH_OF_ISSUER_PUBLIC_KEY;
        const CKA_NAME_HASH_ALGORITHM;
        const CKA_CHECK_VALUE;
        const CKA_KEY_TYPE;
        const CKA_SUBJECT;
        const CKA_ID;
        const CKA_SENSITIVE;
        const CKA_ENCRYPT;
        const CKA_DECRYPT;
        const CKA_WRAP;
        const CKA_UNWRAP;
        const CKA_SIGN;
        const CKA_SIGN_RECOVER;
        const CKA_VERIFY;
        const CKA_VERIFY_RECOVER;
        const CKA_DERIVE;
        const CKA_START_DATE;
        const CKA_END_DATE;
        const CKA_MODULUS;
        const CKA_MODULUS_BITS;
        const CKA_PUBLIC_EXPONENT;
        const CKA_PRIVATE_EXPONENT;
        const CKA_PRIME_1;
        const CKA_PRIME_2;
        const CKA_EXPONENT_1;
        const CKA_EXPONENT_2;
        const CKA_COEFFICIENT;
        const CKA_PUBLIC_KEY_INFO;
        const CKA_PRIME;
        const CKA_SUBPRIME;
        const CKA_BASE;
        const CKA_PRIME_BITS;
        const CKA_SUBPRIME_BITS;
        const CKA_SUB_PRIME_BITS;
        const CKA_VALUE_BITS;
        const CKA_VALUE_LEN;
        const CKA_EXTRACTABLE;
        const CKA_LOCAL;
        const CKA_NEVER_EXTRACTABLE;
        const CKA_ALWAYS_SENSITIVE;
        const CKA_KEY_GEN_MECHANISM;
        const CKA_MODIFIABLE;
        const CKA_COPYABLE;
        const CKA_DESTROYABLE;
        const CKA_ECDSA_PARAMS;
        const CKA_EC_PARAMS;
        const CKA_EC_POINT;
        const CKA_SECONDARY_AUTH;
        const CKA_AUTH_PIN_FLAGS;
        const CKA_ALWAYS_AUTHENTICATE;
        const CKA_WRAP_WITH_TRUSTED;
        const CKA_WRAP_TEMPLATE;
        const CKA_UNWRAP_TEMPLATE;
        const CKA_DERIVE_TEMPLATE;
        const CKA_OTP_FORMAT;
        const CKA_OTP_LENGTH;
        const CKA_OTP_TIME_INTERVAL;
        const CKA_OTP_USER_FRIENDLY_MODE;
        const CKA_OTP_CHALLENGE_REQUIREMENT;
        const CKA_OTP_TIME_REQUIREMENT;
        const CKA_OTP_COUNTER_REQUIREMENT;
        const CKA_OTP_PIN_REQUIREMENT;
        const CKA_OTP_COUNTER;
        const CKA_OTP_TIME;
        const CKA_OTP_USER_IDENTIFIER;
        const CKA_OTP_SERVICE_IDENTIFIER;
        const CKA_OTP_SERVICE_LOGO;
        const CKA_OTP_SERVICE_LOGO_TYPE;
        const CKA_GOSTR3410_PARAMS;
        const CKA_GOSTR3411_PARAMS;
        const CKA_GOST28147_PARAMS;
        const CKA_HW_FEATURE_TYPE;
        const CKA_RESET_ON_INIT;
        const CKA_HAS_RESET;
        const CKA_PIXEL_X;
        const CKA_PIXEL_Y;
        const CKA_RESOLUTION;
        const CKA_CHAR_ROWS;
        const CKA_CHAR_COLUMNS;
        const CKA_COLOR;
        const CKA_BITS_PER_PIXEL;
        const CKA_CHAR_SETS;
        const CKA_ENCODING_METHODS;
        const CKA_MIME_TYPES;
        const CKA_MECHANISM_TYPE;
        const CKA_REQUIRED_CMS_ATTRIBUTES;
        const CKA_DEFAULT_CMS_ATTRIBUTES;
        const CKA_SUPPORTED_CMS_ATTRIBUTES;
        const CKA_ALLOWED_MECHANISMS;
        const CKA_VENDOR_DEFINED;
    }


    //------------ KeyType ---------------------------------------------------

    type KeyType {
         const CKK_RSA;
         const CKK_DSA;
         const CKK_DH;
         const CKK_ECDSA;
         const CKK_EC;
         const CKK_X9_42_DH;
         const CKK_KEA;
         const CKK_GENERIC_SECRET;
         const CKK_RC2;
         const CKK_RC4;
         const CKK_DES;
         const CKK_DES2;
         const CKK_DES3;
         const CKK_CAST;
         const CKK_CAST3;
         const CKK_CAST5;
         const CKK_CAST128;
         const CKK_RC5;
         const CKK_IDEA;
         const CKK_SKIPJACK;
         const CKK_BATON;
         const CKK_JUNIPER;
         const CKK_CDMF;
         const CKK_AES;
         const CKK_BLOWFISH;
         const CKK_TWOFISH;
         const CKK_SECURID;
         const CKK_HOTP;
         const CKK_ACTI;
         const CKK_CAMELLIA;
         const CKK_ARIA;

         const CKK_MD5_HMAC;
         const CKK_SHA_1_HMAC;
         const CKK_RIPEMD128_HMAC;
         const CKK_RIPEMD160_HMAC;
         const CKK_SHA256_HMAC;
         const CKK_SHA384_HMAC;
         const CKK_SHA512_HMAC;
         const CKK_SHA224_HMAC;

         const CKK_SEED;
         const CKK_GOSTR3410;
         const CKK_GOSTR3411;
         const CKK_GOST28147;

         const CKK_VENDOR_DEFINED;
    }


    //------------ HwFeatureType ---------------------------------------------

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


    //------------ MechanismType ---------------------------------------------

    type MechanismType {
        const CKM_RSA_PKCS_KEY_PAIR_GEN;
        const CKM_RSA_PKCS;
        const CKM_RSA_9796;
        const CKM_RSA_X_509;

        const CKM_MD2_RSA_PKCS;
        const CKM_MD5_RSA_PKCS;
        const CKM_SHA1_RSA_PKCS;

        const CKM_RIPEMD128_RSA_PKCS;
        const CKM_RIPEMD160_RSA_PKCS;
        const CKM_RSA_PKCS_OAEP;

        const CKM_RSA_X9_31_KEY_PAIR_GEN;
        const CKM_RSA_X9_31;
        const CKM_SHA1_RSA_X9_31;
        const CKM_RSA_PKCS_PSS;
        const CKM_SHA1_RSA_PKCS_PSS;

        const CKM_DSA_KEY_PAIR_GEN;
        const CKM_DSA;
        const CKM_DSA_SHA1;
        const CKM_DSA_SHA224;
        const CKM_DSA_SHA256;
        const CKM_DSA_SHA384;
        const CKM_DSA_SHA512;

        const CKM_DH_PKCS_KEY_PAIR_GEN;
        const CKM_DH_PKCS_DERIVE;

        const CKM_X9_42_DH_KEY_PAIR_GEN;
        const CKM_X9_42_DH_DERIVE;
        const CKM_X9_42_DH_HYBRID_DERIVE;
        const CKM_X9_42_MQV_DERIVE;

        const CKM_SHA256_RSA_PKCS;
        const CKM_SHA384_RSA_PKCS;
        const CKM_SHA512_RSA_PKCS;
        const CKM_SHA256_RSA_PKCS_PSS;
        const CKM_SHA384_RSA_PKCS_PSS;
        const CKM_SHA512_RSA_PKCS_PSS;

        const CKM_SHA224_RSA_PKCS;
        const CKM_SHA224_RSA_PKCS_PSS;

        const CKM_SHA512_224;
        const CKM_SHA512_224_HMAC;
        const CKM_SHA512_224_HMAC_GENERAL;
        const CKM_SHA512_224_KEY_DERIVATION;
        const CKM_SHA512_256;
        const CKM_SHA512_256_HMAC;
        const CKM_SHA512_256_HMAC_GENERAL;
        const CKM_SHA512_256_KEY_DERIVATION;

        const CKM_SHA512_T;
        const CKM_SHA512_T_HMAC;
        const CKM_SHA512_T_HMAC_GENERAL;
        const CKM_SHA512_T_KEY_DERIVATION;

        const CKM_RC2_KEY_GEN;
        const CKM_RC2_ECB;
        const CKM_RC2_CBC;
        const CKM_RC2_MAC;

        const CKM_RC2_MAC_GENERAL;
        const CKM_RC2_CBC_PAD;

        const CKM_RC4_KEY_GEN;
        const CKM_RC4;
        const CKM_DES_KEY_GEN;
        const CKM_DES_ECB;
        const CKM_DES_CBC;
        const CKM_DES_MAC;

        const CKM_DES_MAC_GENERAL;
        const CKM_DES_CBC_PAD;

        const CKM_DES2_KEY_GEN;
        const CKM_DES3_KEY_GEN;
        const CKM_DES3_ECB;
        const CKM_DES3_CBC;
        const CKM_DES3_MAC;

        const CKM_DES3_MAC_GENERAL;
        const CKM_DES3_CBC_PAD;
        const CKM_DES3_CMAC_GENERAL;
        const CKM_DES3_CMAC;
        const CKM_CDMF_KEY_GEN;
        const CKM_CDMF_ECB;
        const CKM_CDMF_CBC;
        const CKM_CDMF_MAC;
        const CKM_CDMF_MAC_GENERAL;
        const CKM_CDMF_CBC_PAD;

        const CKM_DES_OFB64;
        const CKM_DES_OFB8;
        const CKM_DES_CFB64;
        const CKM_DES_CFB8;

        const CKM_MD2;

        const CKM_MD2_HMAC;
        const CKM_MD2_HMAC_GENERAL;

        const CKM_MD5;

        const CKM_MD5_HMAC;
        const CKM_MD5_HMAC_GENERAL;

        const CKM_SHA_1;

        const CKM_SHA_1_HMAC;
        const CKM_SHA_1_HMAC_GENERAL;

        const CKM_RIPEMD128;
        const CKM_RIPEMD128_HMAC;
        const CKM_RIPEMD128_HMAC_GENERAL;
        const CKM_RIPEMD160;
        const CKM_RIPEMD160_HMAC;
        const CKM_RIPEMD160_HMAC_GENERAL;

        const CKM_SHA256;
        const CKM_SHA256_HMAC;
        const CKM_SHA256_HMAC_GENERAL;
        const CKM_SHA224;
        const CKM_SHA224_HMAC;
        const CKM_SHA224_HMAC_GENERAL;
        const CKM_SHA384;
        const CKM_SHA384_HMAC;
        const CKM_SHA384_HMAC_GENERAL;
        const CKM_SHA512;
        const CKM_SHA512_HMAC;
        const CKM_SHA512_HMAC_GENERAL;
        const CKM_SECURID_KEY_GEN;
        const CKM_SECURID;
        const CKM_HOTP_KEY_GEN;
        const CKM_HOTP;
        const CKM_ACTI;
        const CKM_ACTI_KEY_GEN;

        const CKM_CAST_KEY_GEN;
        const CKM_CAST_ECB;
        const CKM_CAST_CBC;
        const CKM_CAST_MAC;
        const CKM_CAST_MAC_GENERAL;
        const CKM_CAST_CBC_PAD;
        const CKM_CAST3_KEY_GEN;
        const CKM_CAST3_ECB;
        const CKM_CAST3_CBC;
        const CKM_CAST3_MAC;
        const CKM_CAST3_MAC_GENERAL;
        const CKM_CAST3_CBC_PAD;
/* Note that CAST128 and CAST5 are the same algorithm */
        const CKM_CAST5_KEY_GEN;
        const CKM_CAST128_KEY_GEN;
        const CKM_CAST5_ECB;
        const CKM_CAST128_ECB;
        const CKM_CAST5_CBC;
        const CKM_CAST128_CBC;
        const CKM_CAST5_MAC;
        const CKM_CAST128_MAC;
        const CKM_CAST5_MAC_GENERAL;
        const CKM_CAST128_MAC_GENERAL;
        const CKM_CAST5_CBC_PAD;
        const CKM_CAST128_CBC_PAD;
        const CKM_RC5_KEY_GEN;
        const CKM_RC5_ECB;
        const CKM_RC5_CBC;
        const CKM_RC5_MAC;
        const CKM_RC5_MAC_GENERAL;
        const CKM_RC5_CBC_PAD;
        const CKM_IDEA_KEY_GEN;
        const CKM_IDEA_ECB;
        const CKM_IDEA_CBC;
        const CKM_IDEA_MAC;
        const CKM_IDEA_MAC_GENERAL;
        const CKM_IDEA_CBC_PAD;
        const CKM_GENERIC_SECRET_KEY_GEN;
        const CKM_CONCATENATE_BASE_AND_KEY;
        const CKM_CONCATENATE_BASE_AND_DATA;
        const CKM_CONCATENATE_DATA_AND_BASE;
        const CKM_XOR_BASE_AND_DATA;
        const CKM_EXTRACT_KEY_FROM_KEY;
        const CKM_SSL3_PRE_MASTER_KEY_GEN;
        const CKM_SSL3_MASTER_KEY_DERIVE;
        const CKM_SSL3_KEY_AND_MAC_DERIVE;

        const CKM_SSL3_MASTER_KEY_DERIVE_DH;
        const CKM_TLS_PRE_MASTER_KEY_GEN;
        const CKM_TLS_MASTER_KEY_DERIVE;
        const CKM_TLS_KEY_AND_MAC_DERIVE;
        const CKM_TLS_MASTER_KEY_DERIVE_DH;

        const CKM_TLS_PRF;

        const CKM_SSL3_MD5_MAC;
        const CKM_SSL3_SHA1_MAC;
        const CKM_MD5_KEY_DERIVATION;
        const CKM_MD2_KEY_DERIVATION;
        const CKM_SHA1_KEY_DERIVATION;

        const CKM_SHA256_KEY_DERIVATION;
        const CKM_SHA384_KEY_DERIVATION;
        const CKM_SHA512_KEY_DERIVATION;
        const CKM_SHA224_KEY_DERIVATION;

        const CKM_PBE_MD2_DES_CBC;
        const CKM_PBE_MD5_DES_CBC;
        const CKM_PBE_MD5_CAST_CBC;
        const CKM_PBE_MD5_CAST3_CBC;
        const CKM_PBE_MD5_CAST5_CBC;
        const CKM_PBE_MD5_CAST128_CBC;
        const CKM_PBE_SHA1_CAST5_CBC;
        const CKM_PBE_SHA1_CAST128_CBC;
        const CKM_PBE_SHA1_RC4_128;
        const CKM_PBE_SHA1_RC4_40;
        const CKM_PBE_SHA1_DES3_EDE_CBC;
        const CKM_PBE_SHA1_DES2_EDE_CBC;
        const CKM_PBE_SHA1_RC2_128_CBC;
        const CKM_PBE_SHA1_RC2_40_CBC;

        const CKM_PKCS5_PBKD2;

        const CKM_PBA_SHA1_WITH_SHA1_HMAC;

        const CKM_WTLS_PRE_MASTER_KEY_GEN;
        const CKM_WTLS_MASTER_KEY_DERIVE;
        const CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC;
        const CKM_WTLS_PRF;
        const CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE;
        const CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE;

        const CKM_TLS10_MAC_SERVER;
        const CKM_TLS10_MAC_CLIENT;
        const CKM_TLS12_MAC;
        const CKM_TLS12_KDF;
        const CKM_TLS12_MASTER_KEY_DERIVE;
        const CKM_TLS12_KEY_AND_MAC_DERIVE;
        const CKM_TLS12_MASTER_KEY_DERIVE_DH;
        const CKM_TLS12_KEY_SAFE_DERIVE;
        const CKM_TLS_MAC;
        const CKM_TLS_KDF;

        const CKM_KEY_WRAP_LYNKS;
        const CKM_KEY_WRAP_SET_OAEP;

        const CKM_CMS_SIG;
        const CKM_KIP_DERIVE;
        const CKM_KIP_WRAP;
        const CKM_KIP_MAC;

        const CKM_CAMELLIA_KEY_GEN;
        const CKM_CAMELLIA_ECB;
        const CKM_CAMELLIA_CBC;
        const CKM_CAMELLIA_MAC;
        const CKM_CAMELLIA_MAC_GENERAL;
        const CKM_CAMELLIA_CBC_PAD;
        const CKM_CAMELLIA_ECB_ENCRYPT_DATA;
        const CKM_CAMELLIA_CBC_ENCRYPT_DATA;
        const CKM_CAMELLIA_CTR;

        const CKM_ARIA_KEY_GEN;
        const CKM_ARIA_ECB;
        const CKM_ARIA_CBC;
        const CKM_ARIA_MAC;
        const CKM_ARIA_MAC_GENERAL;
        const CKM_ARIA_CBC_PAD;
        const CKM_ARIA_ECB_ENCRYPT_DATA;
        const CKM_ARIA_CBC_ENCRYPT_DATA;

        const CKM_SEED_KEY_GEN;
        const CKM_SEED_ECB;
        const CKM_SEED_CBC;
        const CKM_SEED_MAC;
        const CKM_SEED_MAC_GENERAL;
        const CKM_SEED_CBC_PAD;
        const CKM_SEED_ECB_ENCRYPT_DATA;
        const CKM_SEED_CBC_ENCRYPT_DATA;

        const CKM_SKIPJACK_KEY_GEN;
        const CKM_SKIPJACK_ECB64;
        const CKM_SKIPJACK_CBC64;
        const CKM_SKIPJACK_OFB64;
        const CKM_SKIPJACK_CFB64;
        const CKM_SKIPJACK_CFB32;
        const CKM_SKIPJACK_CFB16;
        const CKM_SKIPJACK_CFB8;
        const CKM_SKIPJACK_WRAP;
        const CKM_SKIPJACK_PRIVATE_WRAP;
        const CKM_SKIPJACK_RELAYX;
        const CKM_KEA_KEY_PAIR_GEN;
        const CKM_KEA_KEY_DERIVE;
        const CKM_KEA_DERIVE;
        const CKM_FORTEZZA_TIMESTAMP;
        const CKM_BATON_KEY_GEN;
        const CKM_BATON_ECB128;
        const CKM_BATON_ECB96;
        const CKM_BATON_CBC128;
        const CKM_BATON_COUNTER;
        const CKM_BATON_SHUFFLE;
        const CKM_BATON_WRAP;

        const CKM_ECDSA_KEY_PAIR_GEN;
        const CKM_EC_KEY_PAIR_GEN;

        const CKM_ECDSA;
        const CKM_ECDSA_SHA1;
        const CKM_ECDSA_SHA224;
        const CKM_ECDSA_SHA256;
        const CKM_ECDSA_SHA384;
        const CKM_ECDSA_SHA512;

        const CKM_ECDH1_DERIVE;
        const CKM_ECDH1_COFACTOR_DERIVE;
        const CKM_ECMQV_DERIVE;

        const CKM_ECDH_AES_KEY_WRAP;
        const CKM_RSA_AES_KEY_WRAP;

        const CKM_JUNIPER_KEY_GEN;
        const CKM_JUNIPER_ECB128;
        const CKM_JUNIPER_CBC128;
        const CKM_JUNIPER_COUNTER;
        const CKM_JUNIPER_SHUFFLE;
        const CKM_JUNIPER_WRAP;
        const CKM_FASTHASH;

        const CKM_AES_KEY_GEN;
        const CKM_AES_ECB;
        const CKM_AES_CBC;
        const CKM_AES_MAC;
        const CKM_AES_MAC_GENERAL;
        const CKM_AES_CBC_PAD;
        const CKM_AES_CTR;
        const CKM_AES_GCM;
        const CKM_AES_CCM;
        const CKM_AES_CTS;
        const CKM_AES_CMAC;
        const CKM_AES_CMAC_GENERAL;

        const CKM_AES_XCBC_MAC;
        const CKM_AES_XCBC_MAC_96;
        const CKM_AES_GMAC;

        const CKM_BLOWFISH_KEY_GEN;
        const CKM_BLOWFISH_CBC;
        const CKM_TWOFISH_KEY_GEN;
        const CKM_TWOFISH_CBC;
        const CKM_BLOWFISH_CBC_PAD;
        const CKM_TWOFISH_CBC_PAD;

        const CKM_DES_ECB_ENCRYPT_DATA;
        const CKM_DES_CBC_ENCRYPT_DATA;
        const CKM_DES3_ECB_ENCRYPT_DATA;
        const CKM_DES3_CBC_ENCRYPT_DATA;
        const CKM_AES_ECB_ENCRYPT_DATA;
        const CKM_AES_CBC_ENCRYPT_DATA;

        const CKM_GOSTR3410_KEY_PAIR_GEN;
        const CKM_GOSTR3410;
        const CKM_GOSTR3410_WITH_GOSTR3411;
        const CKM_GOSTR3410_KEY_WRAP;
        const CKM_GOSTR3410_DERIVE;
        const CKM_GOSTR3411;
        const CKM_GOSTR3411_HMAC;
        const CKM_GOST28147_KEY_GEN;
        const CKM_GOST28147_ECB;
        const CKM_GOST28147;
        const CKM_GOST28147_MAC;
        const CKM_GOST28147_KEY_WRAP;

        const CKM_DSA_PARAMETER_GEN;
        const CKM_DH_PKCS_PARAMETER_GEN;
        const CKM_X9_42_DH_PARAMETER_GEN;
        const CKM_DSA_PROBABLISTIC_PARAMETER_GEN;
        const CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN;

        const CKM_AES_OFB;
        const CKM_AES_CFB64;
        const CKM_AES_CFB8;
        const CKM_AES_CFB128;

        const CKM_AES_CFB1;
        const CKM_AES_KEY_WRAP;
        const CKM_AES_KEY_WRAP_PAD;

        const CKM_RSA_PKCS_TPM_1_1;
        const CKM_RSA_PKCS_OAEP_TPM_1_1;

        const CKM_VENDOR_DEFINED;
    }


    //------------ ObjectClass -----------------------------------------------

    type ObjectClass {
        const CKO_DATA;
        const CKO_CERTIFICATE;
        const CKO_PUBLIC_KEY;
        const CKO_PRIVATE_KEY;
        const CKO_SECRET_KEY;
        const CKO_HW_FEATURE;
        const CKO_DOMAIN_PARAMETERS;
        const CKO_MECHANISM;
        const CKO_OTP_KEY;
        const CKO_VENDOR_DEFINED;
    }


    //------------ State -----------------------------------------------------

    type State {
        const CKS_RO_PUBLIC_SESSION;
        const CKS_RO_USER_FUNCTIONS;
        const CKS_RW_PUBLIC_SESSION;
        const CKS_RW_USER_FUNCTIONS;
        const CKS_RW_SO_FUNCTIONS;
    }


    //------------ UserType --------------------------------------------------

    type UserType {
        const CKU_SO;
        const CKU_USER;
        const CKU_CONTEXT_SPECIFIC;
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



