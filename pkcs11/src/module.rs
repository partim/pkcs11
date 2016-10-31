//! An HSM module.

use std::{io, ptr, result};
use std::borrow::Cow;
use std::path::Path;
use libloading::Library;
use pkcs11_sys as sys;
use super::cryptoki::Cryptoki;
use super::error::{Error, Result};

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
        self.ck.get_info().map(ModuleInfo::new)
    }
}

impl Drop for Module {
    fn drop(&mut self) {
        // XXX Should be panic or something if this fails?
        self.ck.finalize().ok();
    }
}


//------------ ModuleInfo ---------------------------------------------------

pub struct ModuleInfo {
    info: sys::CK_INFO
}

impl ModuleInfo {
    fn new(info: sys::CK_INFO) -> Self {
        ModuleInfo{info: info}
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
