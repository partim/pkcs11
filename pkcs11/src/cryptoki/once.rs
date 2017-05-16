
use std::{mem, ptr};
use libloading::{Library, Symbol};
use pkcs11_sys as sys;
use super::CkError;


//------------ CryptokiOnce --------------------------------------------------

pub struct CryptokiOnce {
    /// The library this Cryptoki implementation came from.
    ///
    /// We only hold onto it here so that it doesn’t get unloaded while we
    /// need it. Normally, we would keep the `Symbol` loaded from it, but we
    /// only need that to get the function list. So we rather keep the
    /// library and the raw function list.
    #[allow(dead_code)]
    library: Library,

    /// The function list retrieved from the library.
    ck: *const sys::CK_FUNCTION_LIST,
}

impl CryptokiOnce {
    pub fn new(lib: Library, args: Option<sys::CK_C_INITIALIZE_ARGS>)
            -> Result<Self, CkError> {
        let ck = unsafe {
            let get_list: Symbol<sys::CK_C_GetFunctionList> =
                                        match lib.get(b"C_GetFunctionList") {
                Ok(list) => list,
                Err(_) => return Err(sys::CKR_GENERAL_ERROR.into())
            };
            let mut list = ptr::null();
            let res = get_list(&mut list);
            if res != sys::CKR_OK {
                return Err(res.into())
            }
            let args_ptr = match args {
                Some(args) => mem::transmute(&args),
                None => ptr::null()
            };
            let res = ((*list).C_Initialize)(args_ptr);
            // Getting "already initialized" is fine. We can use the same
            // module more than once ...
            if res != sys::CKR_OK &&
               res != sys::CKR_CRYPTOKI_ALREADY_INITIALIZED{
                return Err(res.into())
            }
            list
        };
        Ok(CryptokiOnce{library: lib, ck: ck})
    }

    pub fn ck(&self) -> *const sys::CK_FUNCTION_LIST {
        self.ck
    }
}

impl Drop for CryptokiOnce {
    fn drop(&mut self) {
        unsafe {
            ((*self.ck).C_Finalize)(ptr::null());
        }
    }
}


