//! An HSM module.

use std::{io, ptr, result};
use std::borrow::Cow;
use std::path::Path;
use libloading::Library;
use pkcs11_sys as sys;
use super::cryptoki::Cryptoki;
use super::error::{Error, Result};


//------------ Module --------------------------------------------------------

/// An HSM module.
pub struct Module {
    ck: Cryptoki,
}

impl Module {
    pub fn new<P: AsRef<Path>>(path: P) -> NewModuleResult<Self> {
        let lib = try!(Library::new(path.as_ref().as_os_str()));
        let ck = try!(Cryptoki::new(lib));

        // Initialize the module.
        //
        // XXX We’re using the option to rely on operating system locking.
        //     Not sure if that is the smartest option, but let’s run with
        //     it for now.
        let args = sys::CK_C_INITIALIZE_ARGS {
            CreateMutex: None,
            DestroyMutex: None,
            LockMutex: None,
            UnlockMutex: None,
            flags: sys::CKF_OS_LOCKING_OK,
            pReserved: ptr::null()
        };
        try!(ck.initialize(Some(args)));
        Ok(Module{ck: ck})
    }

    pub fn get_info(&self) -> Result<ModuleInfo> {
        let mut res = ModuleInfo::new();
        try!(self.ck.get_info(&mut res.info));
        Ok(res)
    }

    pub fn slots(&self, token_present: bool) -> Result<SlotIter> {
        let count = try!(self.ck.get_slot_list(token_present, None));
        let mut vec = vec![0; count];
        let count = try!(self.ck.get_slot_list(token_present,
                                               Some(&mut vec)));
        vec.truncate(count);
        Ok(SlotIter::new(self, vec))
    }
}

impl Drop for Module {
    fn drop(&mut self) {
        // XXX Should be panic or something if this fails?
        self.ck.finalize().ok();
    }
}


//------------ SlotIter ------------------------------------------------------

pub struct SlotIter<'a> {
    module: &'a Module,
    ids: Vec<sys::CK_SLOT_ID>,
    pos: usize,
}

impl<'a> SlotIter<'a> {
    fn new(module: &'a Module, ids: Vec<sys::CK_SLOT_ID>) -> Self {
        SlotIter{
            module: module, ids: ids,
            pos: 0
        }
    }
}

impl<'a> Iterator for SlotIter<'a> {
    type Item = Slot;

    fn next(&mut self) -> Option<Slot> {
        let id = match self.ids.get(self.pos) {
            Some(id) => *id,
            None => return None
        };
        self.pos += 1;
        Some(Slot::new(self.module.ck.clone(), id))
    }
}


//------------ Slot ----------------------------------------------------------

pub struct Slot {
    ck: Cryptoki,
    id: sys::CK_SLOT_ID
}

impl Slot {
    fn new(ck: Cryptoki, id: sys::CK_SLOT_ID) -> Self {
        Slot{ck: ck, id: id}
    }

    pub fn raw_id(&self) -> sys::CK_SLOT_ID {
        self.id
    }

    pub fn get_slot_info(&self) -> Result<SlotInfo> {
        let mut res = SlotInfo::default();
        try!(self.ck.get_slot_info(self.id, &mut res.info));
        Ok(res)
    }

    pub fn get_token_info(&self) -> Result<TokenInfo> {
        let mut res = TokenInfo::default();
        try!(self.ck.get_token_info(self.id, &mut res.info));
        Ok(res)
    }
}


//------------ ModuleInfo ----------------------------------------------------

#[derive(Debug)]
pub struct ModuleInfo {
    info: sys::CK_INFO
}

impl ModuleInfo {
    fn new() -> Self {
        ModuleInfo{info: sys::CK_INFO {
            cryptokiVersion: sys::CK_VERSION{major: 0, minor: 0},
            manufacturerID: [b' '; 32],
            flags: 0,
            libraryDescription: [b' '; 32],
            libraryVersion: sys::CK_VERSION{major: 0, minor: 0},
        }}
    }

    pub fn cryptoki_version(&self) -> (u8, u8) {
        (self.info.cryptokiVersion.major, self.info.cryptokiVersion.minor)
    }

    pub fn manufacturer_id(&self) -> Cow<str> {
        String::from_utf8_lossy(&self.info.manufacturerID)
    }

    pub fn library_description(&self) -> Cow<str> {
        String::from_utf8_lossy(&self.info.libraryDescription)
    }

    pub fn library_version(&self) -> (u8, u8) {
        (self.info.libraryVersion.major, self.info.libraryVersion.minor)
    }
}


//------------ SlotInfo ------------------------------------------------------

#[derive(Default)]
pub struct SlotInfo {
    info: sys::CK_SLOT_INFO
}

impl SlotInfo {
    pub fn slot_description(&self) -> Cow<str> {
        String::from_utf8_lossy(&self.info.slotDescription)
    }

    pub fn manufacturer_id(&self) -> Cow<str> {
        String::from_utf8_lossy(&self.info.manufacturerID)
    }

    pub fn hardware_version(&self) -> (u8, u8) {
        (self.info.hardwareVersion.major, self.info.hardwareVersion.minor)
    }

    pub fn firmware_version(&self) -> (u8, u8) {
        (self.info.firmwareVersion.major, self.info.firmwareVersion.minor)
    }

    pub fn is_token_present(&self) -> bool {
        self.info.flags & sys::CKF_TOKEN_PRESENT != 0
    }

    pub fn is_removable_device(&self) -> bool {
        self.info.flags & sys::CKF_REMOVABLE_DEVICE != 0
    }

    pub fn is_hw_slot(&self) -> bool {
        self.info.flags & sys::CKF_HW_SLOW != 0
    }
}


//------------ TokenInfo -----------------------------------------------------

#[derive(Default)]
pub struct TokenInfo {
    info: sys::CK_TOKEN_INFO
}

impl TokenInfo {
    pub fn label(&self) -> Cow<str> {
        String::from_utf8_lossy(&self.info.label)
    }

    pub fn manufacturer(&self) -> Cow<str> {
        String::from_utf8_lossy(&self.info.manufacturer)
    }

    pub fn model(&self) -> Cow<str> {
        String::from_utf8_lossy(&self.info.model)
    }

    pub fn has_rng(&self) -> bool {
        self.info.flags & sys::CKF_RNG != 0
    }

    pub fn is_write_protected(&self) -> bool {
        self.info.flags & sys::CKF_WRITE_PROTECTED != 0
    }

    pub fn is_login_required(&self) -> bool {
        self.info.flags & sys::CKF_LOGIN_REQUIRED != 0
    }

    pub fn is_user_pin_initialized(&self) -> bool {
        self.info.flags & sys::CKF_USER_PIN_INITIALIZED != 0
    }

    // ...
}


//------------ NewModuleError ------------------------------------------------

#[derive(Debug)]
pub enum NewModuleError {
    Module(Error),
    Io(io::Error)
}

impl From<Error> for NewModuleError {
    fn from(err: Error) -> Self {
        NewModuleError::Module(err)
    }
}

impl From<io::Error> for NewModuleError {
    fn from(err: io::Error) -> Self {
        NewModuleError::Io(err)
    }
}

impl From<sys::CK_RV> for NewModuleError {
    fn from(err: sys::CK_RV) -> Self {
        NewModuleError::Module(err.into())
    }
}

pub type NewModuleResult<T> = result::Result<T, NewModuleError>;
