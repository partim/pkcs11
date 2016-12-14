
use std::ptr;
use pkcs11_sys as sys;
use super::cryptoki::Cryptoki;
use super::error::Result;


//------------ Session -------------------------------------------------------

pub struct Session {
    ck: Cryptoki,
    handle: sys::CK_SESSION_HANDLE
}

impl Session {
    pub fn new(ck: Cryptoki, slot: sys::CK_SLOT_ID, read_write: bool)
               -> Result<Self> {
        let mut flags = sys::CFK_SERIAL_SESSION;
        if read_write {
            flags |= sys::CFK_RW_SESSION;
        }
        let handle = try!(ck.open_session(slot, flags, ptr::null(), None));
        Ok(Session{ck: ck, handle: handle})
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // XXX Should we do something if this fails?
        self.ck.close_session(self.handle).ok();
    }
}
