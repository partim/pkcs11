
use std::ops;
use pkcs11_sys as sys;


//------------ The Macro for Making the Structs ------------------------------

macro_rules! ck_flags {
    ( $(#[$attr:meta])*
      pub struct $typename:ident {
         $(
             $(#[$item_attr:meta])* flag $item:ident: $value:expr 
         ),*
      }
    ) => {
        $(#[$attr])*
        #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord,
                 PartialEq, PartialOrd)]
        pub struct $typename(sys::CK_FLAGS);

        /// # Constructors for Variants
        ///
        impl $typename {
            $(
                $(#[$item_attr])*
                pub fn $item() -> Self { $typename($value) }
            )*
        }

        /// # Other Methods
        impl $typename {
            pub fn empty() -> Self { $typename(0) }

            pub fn all() -> Self {
                $typename($( $value )|*)
            }

            pub fn is_empty(self) -> bool {
                self.0 == 0
            }

            pub fn is_all(self) -> bool {
                self == Self::all()
            }

            pub fn intersects(self, other: Self) -> bool {
                !(self & other).is_empty()
            }

            pub fn contains(self, other: Self) -> bool {
                (self & other) == other
            }
        }

        impl From<sys::CK_FLAGS> for $typename {
            fn from(value: sys::CK_FLAGS) -> Self {
                $typename(value) & $typename::all()
            }
        }

        impl From<$typename> for sys::CK_FLAGS {
            fn from(value: $typename) -> Self {
                value.0
            }
        }

        impl ops::BitOr for $typename {
            type Output = Self;

            fn bitor(self, other: Self) -> Self {
                $typename(self.0 | other.0)
            }
        }

        impl ops::BitOrAssign for $typename {
            fn bitor_assign(&mut self, other: Self) {
                self.0 |= other.0
            }
        }

        impl ops::BitAnd for $typename {
            type Output = Self;

            fn bitand(self, other: Self) -> Self {
                $typename(self.0 & other.0)
            }
        }

        impl ops::BitAndAssign for $typename {
            fn bitand_assign(&mut self, other: Self) {
                self.0 &= other.0
            }
        }

        impl ops::BitXor for $typename {
            type Output = Self;

            fn bitxor(self, other: Self) -> Self {
                $typename(self.0 ^ other.0)
            }
        }

        impl ops::BitXorAssign for $typename {
            fn bitxor_assign(&mut self, other: Self) {
                self.0 ^= other.0
            }
        }

        impl ops::Sub for $typename {
            type Output = Self;

            fn sub(self, other: Self) -> Self {
                $typename(self.0 & ! other.0)
            }
        }

        impl ops::SubAssign for $typename {
            fn sub_assign(&mut self, other: Self) {
                self.0 &= !other.0
            }
        }

        impl ops::Not for $typename {
            type Output = Self;

            fn not(self) -> Self {
                $typename(!self.0) & $typename::all()
            }
        }
    }
}


//------------ InitializeFlags -----------------------------------------------

ck_flags!{
    /// Flags specifying options when intializing the library.
    pub struct InitializeFlags {
        /// Set if the library is not allowed to spawn OS threads.
        flag library_cant_create_os_threads:
                                     sys::CKF_LIBRARY_CANT_CREATE_OS_THREADS,
        /// Set if the library should use locking provided by the OS.
        flag os_locking_ok: sys::CKF_OS_LOCKING_OK
    }
}


//------------ MechanismFlags --------------------------------------------

ck_flags!{
    /// Flags specifying mechanism capabilities.
    pub struct MechanismFlags {
        /// Set if the mechanism is performed by the device.
        flag hw: sys::CKF_HW,

        /// Set if the mechanism can be used for encryption.
        flag encrypt: sys::CKF_ENCRYPT,

        /// Set if the mechanism can be used for decryption.
        flag decrypt: sys::CKF_DECRYPT,

        /// Set if the mechanism can be used for digests.
        flag digest: sys::CKF_DIGEST,

        /// Set if the mechanism can be used for signing.
        flag sign: sys::CKF_SIGN,

        /// Set if the mechanism can be used for recovering signing.
        flag sign_recover: sys::CKF_SIGN_RECOVER,

        /// Set if the mechanism can be used for verification.
        flag verify: sys::CKF_VERIFY,

        /// Set if the mechanism can be used for recovering verification.
        flag verify_recover: sys::CKF_VERIFY_RECOVER,

        /// Set if the mechanism can be used to generate a secret key.
        flag generate: sys::CKF_GENERATE,

        /// Set if the mechanism can be used to generate a key pair.
        flag generate_key_pair: sys::CKF_GENERATE_KEY_PAIR,

        /// Set if the mechanism can be used to wrap a key.
        flag wrap: sys::CKF_WRAP,

        /// Set if the mechanism can be used to unwrap a key.
        flag unwrap: sys::CKF_UNWRAP,

        /// Set if the mechanism can be used to derive a key.
        flag derive: sys::CKF_DERIVE
    }
}


//------------ SessionFlags --------------------------------------------------

ck_flags! {
    /// The flags defining the type of a session.
    pub struct SessionFlags {
        /// Set if the session is read/write, unset if it is read-only.
        flag rw_session: sys::CKF_RW_SESSION,

        /// Set if the session is to be used by one thread only.
        ///
        /// This flag must always be set in this version of Cryptoki. It is
        /// provided for backwards compatibility only.
        flag serial_session: sys::CKF_SERIAL_SESSION
    }
}


//------------ SlotFlags -------------------------------------------------

ck_flags! {
    /// The flags of a [SlotInfo] struct.
    ///
    /// [SlotInfo]: struct.SlotInfo.html
    pub struct SlotFlags {
        /// Set if a token is present in the slot.
        flag token_present: sys::CKF_TOKEN_PRESENT,

        /// Set if the reader supports removable devices.
        flag removable_device: sys::CKF_REMOVABLE_DEVICE,

        /// Set if the slot is a hardware slot.
        ///
        /// Otherwise, it is a software slot implementing a ”soft token.”
        flag hw_slot: sys::CKF_HW_SLOW
    }
}


//------------ TokenFlags ------------------------------------------------

ck_flags! {
    /// The flags indicating capabilities and status of a token.
    pub struct TokenFlags {
        /// Set if the token has a random number generator.
        flag rng: sys::CKF_RNG,

        /// Set if the token is write-protected.
        flag write_protected: sys::CKF_WRITE_PROTECTED,

        /// Set if there are functions for which a user must be logged in.
        flag login_required: sys::CKF_LOGIN_REQUIRED,

        /// Set if the normal user’s PIN has been initialized.
        flag user_pin_initialized: sys::CKF_USER_PIN_INITIALIZED,

        /// Set if saved session state contains all keys for restore.
        flag restore_key_not_needed: sys::CKF_RESTORE_KEY_NOT_NEEDED,

        /// Set if the token has its own hardware clock.
        flag clock_on_token: sys::CKF_CLOCK_ON_TOKEN,

        /// Set if the token has a “protected authentication path.”
        ///
        /// If it does, a user can log into a token without passing a PIN
        /// through the Cryptoki library.
        flag protected_authentication_path:
            sys::CKF_PROTECTED_AUTHENTICATION_PATH,

        /// Set if the token supports dual crypto operations.
        flag dual_crypto_operations: sys::CKF_DUAL_CRYPTO_OPERATIONS,

        /// Set if the token has been intialized.
        flag token_initialized: sys::CKF_TOKEN_INITIALIZED,

        /// Set if the token supports secondary authentication for
        /// private key objects.
        ///
        /// This flag is deprecated and should not be set.
        flag secondary_authentication: sys::CKF_SECONDARY_AUTHENTICATION,

        /// Set if an incorrect user PIN has been entered at least once
        /// since last successful authentication.
        flag user_pin_count_low: sys::CKF_USER_PIN_COUNT_LOW,

        /// Set if supplying an incorrect user PIN will cause it to
        /// become locked.
        flag user_pin_final_try: sys::CKF_USER_PIN_FINAL_TRY,

        /// Set if the user PIN has been locked.
        ///
        /// User login is not possible into a token with a locked user PIN.
        flag user_pin_locked: sys::CKF_USER_PIN_LOCKED,

        /// Set if the user PIN needs to be changed.
        ///
        /// This happens if the PIN value is the default value set by token
        /// initialization or manufacturing, or the PIN has been expired by the
        /// card.
        flag user_pin_to_be_changed: sys::CKF_USER_PIN_TO_BE_CHANGED,

        /// Set if an incorrect SO PIN has been entered at least once
        /// since last successful authentication.
        flag so_pin_count_low: sys::CKF_SO_PIN_COUNT_LOW,

        /// Set if supplying an incorrect SO PIN will cause it to
        /// become locked.
        flag so_pin_final_try: sys::CKF_SO_PIN_FINAL_TRY,

        /// Set if the SO PIN has been locked.
        ///
        /// SO login is not possible into a token with a locked SO PIN.
        flag so_pin_locked: sys::CKF_SO_PIN_LOCKED,

        /// Set if the SO PIN needs to be changed.
        ///
        /// This happens if the PIN value is the default value set by token
        /// initialization or manufacturing, or the PIN has been expired by the
        /// card.
        flag so_pin_to_be_changed: sys::CKF_SO_PIN_TO_BE_CHANGED,

        /// Set if the token failed a FIPS 140-2 self-test and entered
        /// an error state.
        flag error_state: sys::CKF_ERROR_STATE
    }
}

