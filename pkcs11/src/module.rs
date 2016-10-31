//! An HSM module.

use std::{io, mem, ptr, result};
use std::borrow::Cow;
use std::path::Path;
use libloading::{Library, Symbol};
use pkcs11_sys as sys;
use super::error::{Error, Result};

/// An HSM module.
pub struct Module {
    #[allow(dead_code)]
    library: Library,
    functions: *const sys::CK_FUNCTION_LIST,
}

impl Module {
    pub fn new<P: AsRef<Path>>(path: P) -> NewModuleResult<Self> {
        // Load the library
        let lib = try!(Library::new(path.as_ref().as_os_str()));

        // Get the CK_FUNCTION_LIST pointer.
        let funcs = unsafe {
            let get_list: Symbol<sys::CK_C_GetFunctionList> =
                try!(lib.get(b"C_GetFunctionList"));
            let mut list = ptr::null();
            let res = get_list(&mut list);
            if res != sys::CKR_OK {
                return Err(res.into())
            }
            list
        };

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
        unsafe {
            let args_ptr = mem::transmute(&args);
            let res = ((*funcs).C_Initialize)(args_ptr);
            // Getting "already initialized" is fine. We can use the same
            // module more than once ...
            if res != sys::CKR_OK &&
               res != sys::CKR_CRYPTOKI_ALREADY_INITIALIZED{
                return Err(res.into())
            }
        }
        Ok(Module{library: lib, functions: funcs})
    }

    pub fn get_info(&self) -> Result<ModuleInfo> {
        let info = unsafe {
            let mut info = mem::zeroed();
            let res = ((*self.functions).C_GetInfo)(&mut info);
            if res != sys::CKR_OK {
                return Err(res.into())
            }
            info
        };
        Ok(ModuleInfo { info: info })
    }
}

impl Drop for Module {
    fn drop(&mut self) {
        // XXX Should be panic or something if this fails?
        unsafe { ((*self.functions).C_Finalize)(ptr::null()); }
    }
}


//--- Private Interface wrapping the raw functions.

macro_rules! call_ck {
    ($slf:ident.$f:ident( $( $arg:expr ),* ) ) => {
        match ((*$slf.functions).$f)( $( $arg ),* ) {
            sys::CKR_OK => { }
            err => return Err(err.into())
        }
    }
}

#[allow(dead_code)]
fn ck_len<T: AsRef<[u8]> + ?Sized>(t: &T) -> sys::CK_ULONG {
    t.as_ref().len() as sys::CK_ULONG
}

#[allow(dead_code)]
impl Module {
    fn c_get_info(&self) -> Result<sys::CK_INFO> {
        Ok(unsafe {
            let mut info = mem::zeroed();
            call_ck!(self.C_GetInfo(&mut info));
            info
        })
    }

    fn c_get_slot_list(&self, token_present: bool)
                       -> Result<Vec<sys::CK_SLOT_ID>> {
        let token_present = if token_present { sys::CK_TRUE }
                            else { sys::CK_FALSE };
        Ok(unsafe {
            let mut count = 0;
            call_ck!(self.C_GetSlotList(token_present, ptr::null_mut(),
                                        &mut count));
            let mut list = vec![0; count as usize];
            call_ck!(self.C_GetSlotList(token_present, list.as_mut_ptr(),
                                        &mut count));
            list.truncate(count as usize);
            list
        })
    }

    fn c_get_slot_info(&self, slot_id: sys::CK_SLOT_ID)
                       -> Result<sys::CK_SLOT_INFO> {
        Ok(unsafe {
            let mut info = mem::zeroed();
            call_ck!(self.C_GetSlotInfo(slot_id, &mut info));
            info
        })
    }

    fn c_get_token_info(&self, slot_id: sys::CK_SLOT_ID)
                        -> Result<sys::CK_TOKEN_INFO> {
        Ok(unsafe {
            let mut info = mem::zeroed();
            call_ck!(self.C_GetTokenInfo(slot_id, &mut info));
            info
        })
    }

    fn c_get_mechanism_list(&self, slot_id: sys::CK_SLOT_ID)
                            -> Result<Vec<sys::CK_MECHANISM_TYPE>> {
        Ok(unsafe {
            let mut count = 0;
            call_ck!(self.C_GetMechanismList(slot_id, ptr::null_mut(),
                                             &mut count));
            let mut list = vec![0; count as usize];
            call_ck!(self.C_GetMechanismList(slot_id, list.as_mut_ptr(),
                                             &mut count));
            list.truncate(count as usize);
            list
        })
    }

    fn c_get_mechanism_info(&self, slot_id: sys::CK_SLOT_ID,
                            mechanism: sys::CK_MECHANISM_TYPE)
                            -> Result<sys::CK_MECHANISM_INFO> {
        Ok(unsafe {
            let mut info = mem::zeroed();
            call_ck!(self.C_GetMechanismInfo(slot_id, mechanism, &mut info));
            info
        })
    }

    /// pin can be any length, label must be exactly 32 bytes long. The
    /// method panics if it isn’t.
    fn c_init_token(&self, slot_id: sys::CK_SLOT_ID, pin: &str,
                    label: &str) -> Result<()> {
        assert!(label.as_bytes().len() != 32,
                "token label must be exactly 32 bytes long");
        Ok(unsafe {
            call_ck!(self.C_InitToken(slot_id, pin.as_ptr(), ck_len(pin),
                                      label.as_ptr()))
        })
    }

    fn c_init_pin(&self, session: sys::CK_SESSION_HANDLE, pin: &str)
                  -> Result<()> {
        Ok(unsafe {
            call_ck!(self.C_InitPIN(session, pin.as_ptr(), ck_len(pin)))
        })
    }

    fn c_set_pin(&self, session: sys::CK_SESSION_HANDLE, old_pin: &str,
                 new_pin: &str) -> Result<()> {
        Ok(unsafe {
            call_ck!(self.C_SetPIN(session, old_pin.as_ptr(), ck_len(old_pin),
                                   new_pin.as_ptr(), ck_len(new_pin)))
        })
    }

}


//------------ ModuleInfo ---------------------------------------------------

pub struct ModuleInfo {
    info: sys::CK_INFO
}

impl ModuleInfo {
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
