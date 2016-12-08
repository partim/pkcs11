
use std::ops;
use pkcs11_sys as sys;


//------------ MechanismInfoFlags --------------------------------------------

/// Flags specifying mechanism capabilities.
#[derive(Clone, Copy, Debug, Default)]
pub struct MechanismInfoFlags(sys::CK_FLAGS);

impl MechanismInfoFlags {
    /// Returns whether the mechanism is performed by the device.
    pub fn hw(&self) -> bool {
        self.0 & sys::CKF_HW != 0
    }

    /// Returns whether the mechanism can be used for encryption.
    pub fn encrypt(&self) -> bool {
        self.0 & sys::CKF_ENCRYPT != 0
    }

    /// Returns whether the mechanism can be used for decryption.
    pub fn decrypt(&self) -> bool {
        self.0 & sys::CKF_DECRYPT != 0
    }

    /// Returns whether the mechanism can be used for digests.
    pub fn digest(&self) -> bool {
        self.0 & sys::CKF_DIGEST != 0
    }

    /// Returns whether the mechanism can be used for signing.
    pub fn sign(&self) -> bool {
        self.0 & sys::CKF_SIGN != 0
    }

    /// Returns whether the mechanism can be used for recovering signing.
    pub fn sign_recover(&self) -> bool {
        self.0 & sys::CKF_SIGN_RECOVER != 0
    }

    /// Returns whether the mechanism can be used for verification.
    pub fn verify(&self) -> bool {
        self.0 & sys::CKF_VERIFY != 0
    }

    /// Returns whether the mechanism can be used for recovering verification.
    pub fn verify_recover(&self) -> bool {
        self.0 & sys::CKF_VERIFY_RECOVER != 0
    }

    /// Returns whether the mechanism can be used to generate a secret key.
    pub fn generate(&self) -> bool {
        self.0 & sys::CKF_GENERATE != 0
    }

    /// Returns whether the mechanism can be used to generate a key pair.
    pub fn generate_key_pair(&self) -> bool {
        self.0 & sys::CKF_GENERATE_KEY_PAIR != 0
    }

    /// Returns whether the mechanism can be used to wrap a key.
    pub fn wrap(&self) -> bool {
        self.0 & sys::CKF_WRAP != 0
    }

    /// Returns whether the mechanism can be used to unwrap a key.
    pub fn unwrap(&self) -> bool {
        self.0 & sys::CKF_UNWRAP != 0
    }

    /// Returns whether the mechanism can be used to derive a key.
    pub fn derive(&self) -> bool {
        self.0 & sys::CKF_DERIVE != 0
    }
}

impl From<sys::CK_FLAGS> for MechanismInfoFlags {
    fn from(value: sys::CK_FLAGS) -> Self {
        MechanismInfoFlags(value)
    }
}


//------------ SessionFlags --------------------------------------------------

/// The flags defining the type of a session.
#[derive(Clone, Copy, Debug, Default)]
pub struct SessionFlags(sys::CK_FLAGS);

impl SessionFlags {
    pub fn rw_session() -> Self {
        SessionFlags(sys::CKF_RW_SESSION)
    }

    pub fn serial_session() -> Self {
        SessionFlags(sys::CKF_SERIAL_SESSION)
    }

    pub fn is_rw_session(self) -> bool {
        self.0 & sys::CKF_RW_SESSION != 0
    }

    pub fn is_serial_session(self) -> bool {
        self.0 & sys::CKF_SERIAL_SESSION != 0
    }
}

impl From<sys::CK_FLAGS> for SessionFlags {
    fn from(flags: sys::CK_FLAGS) -> Self {
        SessionFlags(flags)
    }
}

impl From<SessionFlags> for sys::CK_FLAGS {
    fn from(flags: SessionFlags) -> Self {
        flags.0
    }
}

impl ops::BitOr for SessionFlags {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        SessionFlags(self.0 | other.0)
    }
}


//------------ SlotInfoFlags -------------------------------------------------

/// The flags of a [SlotInfo] struct.
///
/// [SlotInfo]: struct.SlotInfo.html
#[derive(Clone, Copy, Debug, Default)]
pub struct SlotInfoFlags(sys::CK_FLAGS);

impl SlotInfoFlags {
    /// Returns whether a token is present in the slot.
    pub fn token_present(&self) -> bool {
        self.0 & sys::CKF_TOKEN_PRESENT != 0
    }

    /// Returns whether the reader supports removable devices.
    pub fn removable_device(&self) -> bool {
        self.0 & sys::CKF_REMOVABLE_DEVICE != 0
    }

    /// Returns whether the slot is a hardware slot.
    ///
    /// Otherwise, it is a software slot implementing a ”soft token.”
    pub fn hw_slot(&self) -> bool {
        self.0 & sys::CKF_HW_SLOW != 0
    }
}

impl From<sys::CK_FLAGS> for SlotInfoFlags {
    fn from(flags: sys::CK_FLAGS) -> Self {
        SlotInfoFlags(flags)
    }
}


//------------ TokenInfoFlags ------------------------------------------------

/// The flags indicating capabilities and status of a token.
#[derive(Clone, Copy, Debug, Default)]
pub struct TokenInfoFlags(sys::CK_FLAGS);

impl TokenInfoFlags {
    /// Returns whether the token has a random number generator.
    pub fn rng(&self) -> bool {
        self.0 & sys::CKF_RNG != 0
    }

    /// Returns whether the token is write-protected.
    ///
    /// Exactly what ’write-protected’ means is not specified in Cryptoki.
    /// An application may be unable to perform certain actions on a
    /// write-protected token. A token may change whether it is
    /// write-protected depending on the session state. For instance, it
    /// may remain write-protected until after a successful login.
    pub fn write_protected(&self) -> bool {
        self.0 & sys::CKF_WRITE_PROTECTED != 0
    }

    /// Returns whether there are functions for which a user must be logged in.
    pub fn login_required(&self) -> bool {
        self.0 & sys::CKF_LOGIN_REQUIRED != 0
    }

    /// Returns whether the normal user’s PIN has been initialized.
    pub fn user_pin_initialized(&self) -> bool {
        self.0 & sys::CKF_USER_PIN_INITIALIZED != 0
    }

    /// Returns whether saved session state contains all keys for restore.
    pub fn restore_key_not_needed(&self) -> bool {
        self.0 & sys::CKF_RESTORE_KEY_NOT_NEEDED != 0
    }

    /// Returns whether the token has its own hardware clock.
    pub fn clock_on_token(&self) -> bool {
        self.0 & sys::CKF_CLOCK_ON_TOKEN != 0
    }

    /// Returns whether the token has a “protected authentication path.”
    ///
    /// If it does, a user can log into a token without passing a PIN
    /// through the Cryptoki library.
    pub fn protected_authentication_path(&self) -> bool {
        self.0 & sys::CKF_PROTECTED_AUTHENTICATION_PATH != 0
    }

    /// Returns whether the token supports dual crypto operations.
    pub fn dual_crypto_operations(&self) -> bool {
        self.0 & sys::CKF_DUAL_CRYPTO_OPERATIONS != 0
    }

    /// Returns whether the token has been intialized.
    ///
    /// If this returns `true` and `Cryptoki::init_token()` is called, the
    /// token will be re-initialized.
    pub fn token_initialized(&self) -> bool {
        self.0 & sys::CKF_TOKEN_INITIALIZED != 0
    }

    /// Returns whether the token supports secondary authentication for
    /// private key objects.
    ///
    /// This flag is deprecated and should not be set.
    pub fn secondary_authentication(&self) -> bool {
        self.0 & sys::CKF_SECONDARY_AUTHENTICATION != 0
    }

    /// Returns whether an incorrect user PIN has been entered at least once
    /// since last successful authentication.
    pub fn user_pin_count_low(&self) -> bool {
        self.0 & sys::CKF_USER_PIN_COUNT_LOW != 0
    }

    /// Returns whether supplying an incorrect user PIN will cause it to
    /// become locked.
    pub fn user_pin_final_try(&self) -> bool {
        self.0 & sys::CKF_USER_PIN_FINAL_TRY != 0
    }

    /// Returns whether the user PIN has been locked.
    ///
    /// User login is not possible into a token with a locked user PIN.
    pub fn user_pin_locked(&self) -> bool {
        self.0 & sys::CKF_USER_PIN_LOCKED != 0
    }

    /// Returns whether the user PIN needs to be changed.
    ///
    /// This happens if the PIN value is the default value set by token
    /// initialization or manufacturing, or the PIN has been expired by the
    /// card.
    pub fn user_pin_to_be_changed(&self) -> bool {
        self.0 & sys::CKF_USER_PIN_TO_BE_CHANGED != 0
    }

    /// Returns whether an incorrect SO PIN has been entered at least once
    /// since last successful authentication.
    pub fn so_pin_count_low(&self) -> bool {
        self.0 & sys::CKF_SO_PIN_COUNT_LOW != 0
    }

    /// Returns whether supplying an incorrect SO PIN will cause it to
    /// become locked.
    pub fn so_pin_final_try(&self) -> bool {
        self.0 & sys::CKF_SO_PIN_FINAL_TRY != 0
    }

    /// Returns whether the SO PIN has been locked.
    ///
    /// SO login is not possible into a token with a locked SO PIN.
    pub fn so_pin_locked(&self) -> bool {
        self.0 & sys::CKF_SO_PIN_LOCKED != 0
    }

    /// Returns whether the SO PIN needs to be changed.
    ///
    /// This happens if the PIN value is the default value set by token
    /// initialization or manufacturing, or the PIN has been expired by the
    /// card.
    pub fn so_pin_to_be_changed(&self) -> bool {
        self.0 & sys::CKF_SO_PIN_TO_BE_CHANGED != 0
    }

    /// Returns whether the token failed a FIPS 140-2 self-test and entered
    /// an error state.
    pub fn error_state(&self) -> bool {
        self.0 & sys::CKF_ERROR_STATE != 0
    }
}

impl From<sys::CK_FLAGS> for TokenInfoFlags {
    fn from(flags: sys::CK_FLAGS) -> Self {
        TokenInfoFlags(flags)
    }
}

