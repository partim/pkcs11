
use std::{mem, ptr, slice};
use std::borrow::Cow;
use std::marker::PhantomData;
use pkcs11_sys as sys;
use super::{from_ck_long, to_ck_long};
use super::{SlotId, State};
use super::{MechanismInfoFlags, SessionFlags, SlotInfoFlags, TokenInfoFlags};


//------------ Attribute -----------------------------------------------------

pub struct Attribute<'a> {
    inner: sys::CK_ATTRIBUTE,
    marker: PhantomData<&'a u8>,
}

/// # Creation
///
impl<'a> Attribute<'a> {
    fn new<T: ?Sized>(attr: sys::CK_ATTRIBUTE_TYPE, ptr: *const T, len: usize)
                      -> Self {
        Attribute {
            inner: sys::CK_ATTRIBUTE {
                aType: attr,
                pValue: ptr as *const _,
                ulValueLen: to_ck_long(len)
            },
            marker: PhantomData
        }
    }

    pub fn from_none(attr: sys::CK_ATTRIBUTE_TYPE) -> Self {
        Self::new(attr, ptr::null() as *const u8, 0)
    }

    pub fn from_ref<T>(attr: sys::CK_ATTRIBUTE_TYPE, val: &'a T) -> Self {
        Self::new(attr, val, mem::size_of::<T>())
    }

    pub fn from_bytes(attr: sys::CK_ATTRIBUTE_TYPE, value: &'a [u8]) -> Self {
        Self::new(attr, value.as_ptr(), value.len())
    }
}

/// # Access to Data
///
impl<'a> Attribute<'a> {
    pub fn len(&self) -> Option<usize> {
        if self.inner.ulValueLen == sys::CK_UNAVAILABLE_INFORMATION {
            None
        }
        else {
            Some(from_ck_long(self.inner.ulValueLen))
        }
    }

    pub fn bytes(&self) -> Option<&'a [u8]> {
        if self.inner.pValue == ptr::null() {
            None
        }
        else {
            self.len().map(|len| unsafe {
                slice::from_raw_parts(mem::transmute(self.inner.pValue), len)
            })
        }
    }

    pub fn value<T>(&self) -> Option<&T> {
        self.len().map(|len| unsafe {
            assert_eq!(mem::size_of::<T>(), len);
            mem::transmute(self.inner.pValue)
        })
    }

    pub fn value_mut<T>(&mut self) -> Option<&mut T> {
        self.len().map(|len| unsafe {
            assert_eq!(mem::size_of::<T>(), len);
            mem::transmute(self.inner.pValue)
        })
    }
}


//------------ Info ----------------------------------------------------------

/// A struct providing general information about the system.
#[derive(Clone, Debug, Default)]
pub struct Info(sys::CK_INFO);

impl Info {
    /// Returns the Cryptoki interface version number.
    ///
    /// The version is returned as a pair of `u8`s with the first element
    /// the major version and the second element the minor.
    pub fn cryptoki_version(&self) -> (u8, u8) {
        (self.0.cryptokiVersion.major, self.0.cryptokiVersion.minor)
    }

    /// Returns the ID of the Cryptoki library manufacturer.
    ///
    /// Returns a cow in case the library returns an illegal string. In this
    /// case, the illegal characters will be replaced with the Unicode
    /// replacement character.
    pub fn manufacturer_id(&self) -> Cow<str> {
        String::from_utf8_lossy(&self.0.manufacturerID)
    }

    /// Returns a description of the library.
    ///
    /// Returns a cow in case the library returns an illegal string. In this
    /// case, the illegal characters will be replaced with the Unicode
    /// replacement character.
    pub fn library_description(&self) -> Cow<str> {
        String::from_utf8_lossy(&self.0.libraryDescription)
    }

    /// Returns the Cryptoki library version.
    ///
    /// The version is returned as a pair of `u8`s with the first element
    /// the major version and the second element the minor.
    pub fn library_version(&self) -> (u8, u8) {
        (self.0.libraryVersion.major, self.0.libraryVersion.minor)
    }
}

impl AsMut<sys::CK_INFO> for Info {
    fn as_mut(&mut self) -> &mut sys::CK_INFO {
        &mut self.0
    }
}


//------------ MechanismInfo -------------------------------------------------

/// A structure that provides information about a particular mechanism
#[derive(Clone, Debug, Default)]
pub struct MechanismInfo(sys::CK_MECHANISM_INFO);

impl MechanismInfo {
    /// Returns the minimum size of the key for the mechanism.
    ///
    /// Whether this is measured in bits or in bytes is mechanism-dependent.
    /// For some mechanisms, the value has no meaning.
    pub fn min_key_size(&self) -> usize {
        from_ck_long(self.0.ulMinKeySize)
    }

    /// Returns the maximum size of the key for the mechanism.
    ///
    /// Whether this is measured in bits or in bytes is mechanism-dependent.
    /// For some mechanisms, the value has no meaning.
    pub fn max_key_size(&self) -> usize {
        from_ck_long(self.0.ulMaxKeySize)
    }

    /// Returns the flags specifying mechanism capabilities.
    pub fn flags(&self) -> MechanismInfoFlags {
        self.0.flags.into()
    }
}

impl AsMut<sys::CK_MECHANISM_INFO> for MechanismInfo {
    fn as_mut(&mut self) -> &mut sys::CK_MECHANISM_INFO {
        &mut self.0
    }
}


//------------ SessionInfo ---------------------------------------------------

/// A structure providing information about a session.
#[derive(Clone, Debug, Default)]
pub struct SessionInfo(sys::CK_SESSION_INFO);

impl SessionInfo {
    /// Returns the ID of the slot that interfaces with the token.
    pub fn slot_id(&self) -> SlotId {
        self.0.slotID.into()
    }

    /// Returns the state of the session.
    pub fn state(&self) -> State {
        // The unwrap here is somewhat unfortunate. However, since the only
        // way to create a value of this type is via
        // `Cryptoki::get_session_info()` and that checks already, it ought
        // to be okay.
        State::try_from(self.0.state).unwrap()
    }

    /// Returns the flags that define the type of the session.
    pub fn flags(&self) -> SessionFlags {
        self.0.flags.into()
    }

    /// Returns an error code defined by the device.
    ///
    /// Used for errors not covered by Cryptoki.
    pub fn device_error(&self) -> usize {
        from_ck_long(self.0.ulDeviceError)
    }
}

impl AsMut<sys::CK_SESSION_INFO> for SessionInfo {
    fn as_mut(&mut self) -> &mut sys::CK_SESSION_INFO {
        &mut self.0
    }
}


//------------ SlotInfo ------------------------------------------------------

/// A structure providing information about a slot.
#[derive(Clone, Debug, Default)]
pub struct SlotInfo(sys::CK_SLOT_INFO);

impl SlotInfo {
    /// Returns a description of the slot.
    ///
    /// Returns a cow in case the library returns an illegal string. In this
    /// case, the illegal characters will be replaced with the Unicode
    /// replacement character.
    pub fn slot_description(&self) -> Cow<str> {
        String::from_utf8_lossy(&self.0.slotDescription)
    }

    /// Returns the ID of the slot manufacturer.
    ///
    /// Returns a cow in case the library returns an illegal string. In this
    /// case, the illegal characters will be replaced with the Unicode
    /// replacement character.
    pub fn manufacturer_id(&self) -> Cow<str> {
        String::from_utf8_lossy(&self.0.manufacturerID)
    }

    /// Returns the version number of the slot’s hardware.
    ///
    /// The version is returned as a pair of `u8`s with the first element
    /// the major version and the second element the minor.
    pub fn hardware_version(&self) -> (u8, u8) {
        (self.0.hardwareVersion.major, self.0.hardwareVersion.minor)
    }

    /// Returns the version number of the slot’s firmware.
    ///
    /// The version is returned as a pair of `u8`s with the first element
    /// the major version and the second element the minor.
    pub fn firmware_version(&self) -> (u8, u8) {
        (self.0.firmwareVersion.major, self.0.firmwareVersion.minor)
    }

    /// Returns flags that provide the capabilities of the slot.
    pub fn flags(&self) -> SlotInfoFlags {
        self.0.flags.into()
    }
}

impl AsMut<sys::CK_SLOT_INFO> for SlotInfo {
    fn as_mut(&mut self) -> &mut sys::CK_SLOT_INFO {
        &mut self.0
    }
}


//------------ TokenInfo -----------------------------------------------------

/// A structure providing information about a token.
#[derive(Clone, Debug, Default)]
pub struct TokenInfo(sys::CK_TOKEN_INFO);

impl TokenInfo {
    /// Returns the application-defined label of the token.
    ///
    /// This label is assigned to the token during initialization.
    pub fn label(&self) -> Cow<str> {
        String::from_utf8_lossy(&self.0.label)
    }

    /// Returns the ID of the device manufacturer.
    ///
    /// Returns a cow in case the library returns an illegal string. In this
    /// case, the illegal characters will be replaced with the Unicode
    /// replacement character.
    pub fn manufacturer(&self) -> Cow<str> {
        String::from_utf8_lossy(&self.0.manufacturer)
    }

    /// Returns the model of the device.
    ///
    /// Returns a cow in case the library returns an illegal string. In this
    /// case, the illegal characters will be replaced with the Unicode
    /// replacement character.
    pub fn model(&self) -> Cow<str> {
        String::from_utf8_lossy(&self.0.model)
    }

    /// Returns the serial number of the device.
    ///
    /// Returns a cow in case the library returns an illegal string. In this
    /// case, the illegal characters will be replaced with the Unicode
    /// replacement character.
    pub fn serial_number(&self) -> Cow<str> {
        String::from_utf8_lossy(&self.0.serialNumber)
    }

    /// Returns the flags indicating capabilities and status of the device.
    pub fn flags(&self) -> TokenInfoFlags {
        self.0.flags.into()
    }

    /// Returns the maximum number of sessions for a single application.
    ///
    /// Returns `None` if token or library are unable or unwilling to reveal
    /// this information.
    pub fn max_session_count(&self) -> Option<MaxSessionCount> {
        MaxSessionCount::new(self.0.ulMaxSessionCount)
    }

    /// Returns the number of sessions the application has with the token.
    ///
    /// Returns `None` if token or library are unable or unwilling to reveal
    /// this information.
    pub fn session_count(&self) -> Option<usize> {
        match self.0.ulSessionCount {
            sys::CK_UNAVAILABLE_INFORMATION => None,
            value => Some(from_ck_long(value))
        }
    }

    /// Returns the maximum number of read-write sessions.
    ///
    /// Returns `None` if token or library are unable or unwilling to reveal
    /// this information.
    pub fn max_rw_session_count(&self) -> Option<MaxSessionCount> {
        MaxSessionCount::new(self.0.ulMaxRwSessionCount)
    }

    /// Returns the number of read-write sessions the application has.
    ///
    /// Returns `None` if token or library are unable or unwilling to reveal
    /// this information.
    pub fn rw_session_count(&self) -> Option<usize> {
        match self.0.ulRwSessionCount {
            sys::CK_UNAVAILABLE_INFORMATION => None,
            value => Some(from_ck_long(value))
        }
    }

    /// Returns the maximum length of a PIN in bytes.
    pub fn max_pin_len(&self) -> usize {
        from_ck_long(self.0.ulMaxPinLen)
    }

    /// Returns the minimum length of a PIN in bytes.
    pub fn min_pin_len(&self) -> usize {
        from_ck_long(self.0.ulMinPinLen)
    }

    /// Returns the total amount of memory in the token for public objects.
    ///
    /// Returns `None` if token or library are unable or unwilling to reveal
    pub fn total_public_memory(&self) -> Option<usize> {
        match self.0.ulTotalPublicMemory {
            sys::CK_UNAVAILABLE_INFORMATION => None,
            value => Some(from_ck_long(value))
        }
    }

    /// Returns the amount of memory currently available for public objects.
    ///
    /// Returns `None` if token or library are unable or unwilling to reveal
    pub fn free_public_memory(&self) -> Option<usize> {
        match self.0.ulFreePublicMemory {
            sys::CK_UNAVAILABLE_INFORMATION => None,
            value => Some(from_ck_long(value))
        }
    }

    /// Returns the total amount of memory in the token for private objects.
    ///
    /// Returns `None` if token or library are unable or unwilling to reveal
    pub fn total_private_memory(&self) -> Option<usize> {
        match self.0.ulTotalPrivateMemory {
            sys::CK_UNAVAILABLE_INFORMATION => None,
            value => Some(from_ck_long(value))
        }
    }

    /// Returns the amount of memory currently available for private objects.
    ///
    /// Returns `None` if token or library are unable or unwilling to reveal
    pub fn free_private_memory(&self) -> Option<usize> {
        match self.0.ulFreePrivateMemory {
            sys::CK_UNAVAILABLE_INFORMATION => None,
            value => Some(from_ck_long(value))
        }
    }

    /// Returns the version number of the tokens’s hardware.
    ///
    /// The version is returned as a pair of `u8`s with the first element
    /// the major version and the second element the minor.
    pub fn hardware_version(&self) -> (u8, u8) {
        (self.0.hardwareVersion.major, self.0.hardwareVersion.minor)
    }

    /// Returns the version number of the token’s firmware.
    ///
    /// The version is returned as a pair of `u8`s with the first element
    /// the major version and the second element the minor.
    pub fn firmware_version(&self) -> (u8, u8) {
        (self.0.firmwareVersion.major, self.0.firmwareVersion.minor)
    }

    /// Returns the token’s current time.
    ///
    /// The time is given as a string of 16 ASCII digits in the format
    /// `YYYYMMDDhhmmss00`. It’s value only makes sense if the token indeed
    /// has a clock.
    pub fn utc_time(&self) -> &[u8] {
        &self.0.utcTime[..]
    }
}

impl AsMut<sys::CK_TOKEN_INFO> for TokenInfo {
    fn as_mut(&mut self) -> &mut sys::CK_TOKEN_INFO {
        &mut self.0
    }
}


//----------- MaxSessionCount ------------------------------------------------

/// The maximum number of concurrent sessions.
#[derive(Clone, Copy, Debug)]
pub enum MaxSessionCount {
    Finite(usize),
    EffectivelyInfinite,
}

impl MaxSessionCount {
    fn new(value: sys::CK_ULONG) -> Option<Self> {
        match value {
            sys::CK_UNAVAILABLE_INFORMATION
                => None,
            sys::CK_EFFECTIVELY_INFINITE
                => Some(MaxSessionCount::EffectivelyInfinite),
            _ => Some(MaxSessionCount::Finite(from_ck_long(value)))
        }
    }
}




