//! Safe wrappers for the Cryptoki API.
#![allow(dead_code)] // XXX for now ...

use std::{io, mem, ptr, slice};
use std::marker::PhantomData;
use std::sync::Arc;
use libloading::{Library, Symbol};
use pkcs11_sys as sys;
use super::error::{Error, Result};


//------------ Cryptoki ------------------------------------------------------

#[derive(Clone)]
pub struct Cryptoki {
    /// The library this Cryptoki implementation came from.
    ///
    /// We only hold onto it here so that it doesn’t get unloaded while we
    /// need it. Normally, we would keep the `Symbol` loaded from it, but we
    /// only need that to get the function list. So we rather keep the
    /// library and the raw function list.
    #[allow(dead_code)]
    library: Arc<Library>,

    /// The function list retrieved from the library.
    ck: *const sys::CK_FUNCTION_LIST,
}

impl<'a> Cryptoki {
    pub fn new(lib: Library) -> io::Result<Self> {
        let ck = unsafe {
            let get_list: Symbol<sys::CK_C_GetFunctionList> =
                try!(lib.get(b"C_GetFunctionList"));
            let mut list = ptr::null();
            let res = get_list(&mut list);
            if res != sys::CKR_OK {
                return Err(io::Error::new(io::ErrorKind::Other,
                                          ::std::error::Error::description(
                                                &Error::from(res))))
            }
            list
        };
        Ok(Cryptoki{library: Arc::new(lib), ck: ck})
    }
}


macro_rules! call_ck {
    ($slf:ident.$f:ident( $( $arg:expr ),* ) ) => {
        match ((*$slf.ck).$f)( $( $arg ),* ) {
            sys::CKR_OK => { }
            err => return Err(err.into())
        }
    }
}


impl Cryptoki {
    pub fn initialize(&self, args: Option<sys::CK_C_INITIALIZE_ARGS>)
                      -> Result<()> {
        unsafe {
            let args_ptr = match args {
                Some(args) => mem::transmute(&args),
                None => ptr::null()
            };
            let res = ((*self.ck).C_Initialize)(args_ptr);
            // Getting "already initialized" is fine. We can use the same
            // module more than once ...
            if res != sys::CKR_OK &&
               res != sys::CKR_CRYPTOKI_ALREADY_INITIALIZED{
                return Err(res.into())
            }
        }
        Ok(())
    }

    pub fn finalize(&self) -> Result<()> {
        Ok(unsafe {
            call_ck!(self.C_Finalize(ptr::null()))
        })
    }

    pub fn get_info(&self, info: &mut sys::CK_INFO) -> Result<()> {
        Ok(unsafe {
            call_ck!(self.C_GetInfo(info));
        })
    }

    pub fn get_slot_list(&self, token_present: bool,
                         slot_list: Option<&mut [sys::CK_SLOT_ID]>)
                         -> Result<usize> {
        let token_present = if token_present { sys::CK_TRUE }
                            else { sys::CK_FALSE };
        Ok(unsafe {
            let mut res = opt_len(&slot_list);
            call_ck!(self.C_GetSlotList(token_present,
                                        opt_mut_ptr(slot_list),
                                        &mut res));
            from_ck_long(res)
        })
    }

    pub fn get_slot_info(&self, slot_id: sys::CK_SLOT_ID,
                         info: &mut sys::CK_SLOT_INFO)
                       -> Result<()> {
        Ok(unsafe {
            call_ck!(self.C_GetSlotInfo(slot_id, info));
        })
    }

    pub fn get_token_info(&self, slot_id: sys::CK_SLOT_ID,
                          info: &mut sys::CK_TOKEN_INFO)
                        -> Result<()> {
        Ok(unsafe {
            call_ck!(self.C_GetTokenInfo(slot_id, info));
        })
    }

    pub fn get_mechanism_list(&self, slot_id: sys::CK_SLOT_ID,
                              list: Option<&mut [sys::CK_MECHANISM_TYPE]>)
                            -> Result<usize> {
        Ok(unsafe { 
            let mut res = opt_len(&list);
            call_ck!(self.C_GetMechanismList(slot_id,
                                             opt_mut_ptr(list),
                                             &mut res));
            from_ck_long(res)
        })
    }

    pub fn get_mechanism_info(&self, slot_id: sys::CK_SLOT_ID,
                              mechanism: sys::CK_MECHANISM_TYPE,
                              info: &mut sys::CK_MECHANISM_INFO)
                              -> Result<()> {
        Ok(unsafe {
            call_ck!(self.C_GetMechanismInfo(slot_id, mechanism, info));
        })
    }

    /// pin can be any length, label must be exactly 32 bytes long. Returns
    /// `CKR_ARGUMENTS_BAD` if it isn’t.
    pub fn init_token(&self, slot_id: sys::CK_SLOT_ID, pin: &str,
                    label: &str) -> Result<()> {
        if label.as_bytes().len() != 32 {
            return Err(sys::CKR_ARGUMENTS_BAD.into())
        }
        Ok(unsafe {
            call_ck!(self.C_InitToken(slot_id, pin.as_ptr(), ck_len(pin),
                                      label.as_ptr()))
        })
    }

    pub fn init_pin(&self, session: sys::CK_SESSION_HANDLE, pin: &str)
                  -> Result<()> {
        Ok(unsafe {
            call_ck!(self.C_InitPIN(session, pin.as_ptr(), ck_len(pin)))
        })
    }

    pub fn set_pin(&self, session: sys::CK_SESSION_HANDLE, old_pin: &str,
                 new_pin: &str) -> Result<()> {
        Ok(unsafe {
            call_ck!(self.C_SetPIN(session, old_pin.as_ptr(), ck_len(old_pin),
                                   new_pin.as_ptr(), ck_len(new_pin)))
        })
    }

    pub fn open_session(&self, slot_id: sys::CK_SLOT_ID, flags: sys::CK_FLAGS,
                        app: *const sys::CK_VOID,
                        notify: Option<sys::CK_NOTIFY>)
                        -> Result<sys::CK_SESSION_HANDLE> {
        Ok(unsafe {
            let mut handle = 0;
            call_ck!(self.C_OpenSession(slot_id, flags, app, notify,
                                        &mut handle));
            handle
        })
    }

    pub fn close_session(&self, session: sys::CK_SESSION_HANDLE)
                         -> Result<()> {
        Ok(unsafe { call_ck!(self.C_CloseSession(session)) })
    }

    pub fn close_all_sessions(&self, slot_id: sys::CK_SLOT_ID) -> Result<()> {
        Ok(unsafe { call_ck!(self.C_CloseAllSessions(slot_id)) })
    }

    pub fn get_session_info(&self, session: sys::CK_SESSION_HANDLE)
                            -> Result<sys::CK_SESSION_INFO> {
        Ok(unsafe {
            let mut info = mem::zeroed();
            call_ck!(self.C_GetSessionInfo(session, &mut info));
            info
        })
    }

    pub fn get_operation_state(&self, session: sys::CK_SESSION_HANDLE,
                               state: Option<&mut [u8]>) -> Result<usize> {
        Ok(unsafe {
            let mut res = opt_len(&state);
            call_ck!(self.C_GetOperationState(session, opt_mut_ptr(state),
                                              &mut res));
            from_ck_long(res)
        })
    }

    pub fn set_operation_state(&self, session: sys::CK_SESSION_HANDLE,
                               operation_state: &[u8],
                               encryption_key: sys::CK_OBJECT_HANDLE,
                               authentication_key: sys::CK_OBJECT_HANDLE)
                               -> Result<()> {
        Ok(unsafe { call_ck!(
            self.C_SetOperationState(session, operation_state.as_ptr(),
                                     ck_len(operation_state),
                                     encryption_key, authentication_key)
        )})
    }

    pub fn login(&self, session: sys::CK_SESSION_HANDLE,
                 user_type: sys::CK_USER_TYPE, pin: &str) -> Result<()> {
        Ok(unsafe { call_ck!(
            self.C_Login(session, user_type, pin.as_ptr(), ck_len(pin))
        )})
    }

    pub fn logout(&self, session: sys::CK_SESSION_HANDLE) -> Result<()> {
        Ok(unsafe { call_ck!(self.C_Logout(session)) })
    }

    pub fn create_object<'a, T>(&self, session: sys::CK_SESSION_HANDLE,
                                template: T) -> Result<sys::CK_OBJECT_HANDLE>
                         where T: AsRef<[Attribute<'a>]> {
        Ok(unsafe {
            let mut res = 0;
            let (ptr, len) = translate_template(template);
            call_ck!(self.C_CreateObject(session, ptr, len, &mut res));
            res
        })
    }

    pub fn copy_object<'a, T>(&self, session: sys::CK_SESSION_HANDLE,
                              object: sys::CK_OBJECT_HANDLE, template: T)
                              -> Result<sys::CK_OBJECT_HANDLE> 
                       where T: AsRef<[Attribute<'a>]> {
        Ok(unsafe {
            let mut res = 0;
            let (ptr, len) = translate_template(template);
            call_ck!(self.C_CopyObject(session, object, ptr, len, &mut res));
            res
        })
    }

    pub fn destroy_object(&self, session: sys::CK_SESSION_HANDLE,
                          object: sys::CK_OBJECT_HANDLE) -> Result<()> {
        Ok(unsafe { call_ck!(self.C_DestroyObject(session, object)) })
    }

    pub fn get_object_size(&self, session: sys::CK_SESSION_HANDLE,
                           object: sys::CK_OBJECT_HANDLE)
                           -> Result<sys::CK_ULONG> {
        Ok(unsafe {
            let mut res = 0;
            call_ck!(self.C_GetObjectSize(session, object, &mut res));
            res
        })
    }

    pub fn get_attribute_value<'a, T>(&self, session: sys::CK_SESSION_HANDLE,
                                      object: sys::CK_OBJECT_HANDLE,
                                      mut template: T) -> Result<()>
                               where T: AsMut<[Attribute<'a>]> {
        Ok(unsafe {
            let template: &mut [sys::CK_ATTRIBUTE]
                = mem::transmute(template.as_mut());
            call_ck!(self.C_GetAttributeValue(session, object,
                                              template.as_mut_ptr(),
                                              ck_len(template)))
        })
    }

    pub fn set_attribute_value<'a, T>(&self, session: sys::CK_SESSION_HANDLE,
                                      object: sys::CK_OBJECT_HANDLE,
                                      template: T) -> Result<()>
                               where T: AsRef<[Attribute<'a>]> {
        Ok(unsafe {
            let (ptr, len) = translate_template(template);
            call_ck!(self.C_SetAttributeValue(session, object, ptr, len))
        })
    }

    pub fn find_objects_init<'a, T>(&self, session: sys::CK_SESSION_HANDLE,
                                    template: T) -> Result<()>
                             where T: AsRef<[Attribute<'a>]> {
        Ok(unsafe {
            let (ptr, len) = translate_template(template);
            call_ck!(self.C_FindObjectsInit(session, ptr, len))
        })
    }

    pub fn find_objects(&self, session: sys::CK_SESSION_HANDLE,
                        buf: &mut [sys::CK_OBJECT_HANDLE])
                        -> Result<usize> {
        Ok(unsafe {
            let mut res = 0;
            call_ck!(self.C_FindObjects(session, buf.as_mut_ptr(),
                                        ck_len(buf), &mut res));
            from_ck_long(res)
        })
    }

    pub fn find_objects_final(&self, session: sys::CK_SESSION_HANDLE)
                              -> Result<()> {
        Ok(unsafe {
            call_ck!(self.C_FindObjectsFinal(session))
        })
    }

    pub fn encrypt_init(&self, session: sys::CK_SESSION_HANDLE,
                        mechanism: &sys::CK_MECHANISM,
                        key: sys::CK_OBJECT_HANDLE) -> Result<()> {
        Ok(unsafe {
            call_ck!(self.C_EncryptInit(session, mechanism, key))
        })
    }

    pub fn encrypt(&self, session: sys::CK_SESSION_HANDLE,
                   data: &[u8], encrypted_data: Option<&mut [u8]>)
                   -> Result<usize> {
        Ok(unsafe {
            let mut res = opt_len(&encrypted_data);
            call_ck!(self.C_Encrypt(session, data.as_ptr(), ck_len(data),
                                    opt_mut_ptr(encrypted_data), &mut res));
            from_ck_long(res)
        })
    }

    pub fn encrypt_update(&self, session: sys::CK_SESSION_HANDLE,
                          part: &[u8], encrypted_part: Option<&mut [u8]>)
                          -> Result<usize> {
        Ok(unsafe {
            let mut res = opt_len(&encrypted_part);
            call_ck!(self.C_EncryptUpdate(session, part.as_ptr(),
                                          ck_len(part),
                                          opt_mut_ptr(encrypted_part),
                                          &mut res));
            from_ck_long(res)
        })
    }

    pub fn encrypt_final(&self, session: sys::CK_SESSION_HANDLE,
                         last_encrypted_part: Option<&mut [u8]>)
                         -> Result<usize> {
        Ok(unsafe {
            let mut res = opt_len(&last_encrypted_part);
            call_ck!(self.C_EncryptFinal(session,
                                         opt_mut_ptr(last_encrypted_part),
                                         &mut res));
            from_ck_long(res)
        })
    }

    pub fn decrypt_init(&self, session: sys::CK_SESSION_HANDLE,
                        mechanism: &sys::CK_MECHANISM,
                        key: sys::CK_OBJECT_HANDLE) -> Result<()> {
        Ok(unsafe { call_ck!(self.C_DecryptInit(session, mechanism, key)) })
    }

    pub fn decrypt(&self, session: sys::CK_SESSION_HANDLE,
                   encrypted_data: &[u8], data: Option<&mut [u8]>)
                   -> Result<usize> {
        Ok(unsafe {
            let mut res = opt_len(&data);
            call_ck!(self.C_Decrypt(session, encrypted_data.as_ptr(),
                                    ck_len(encrypted_data),
                                    opt_mut_ptr(data), &mut res));
            from_ck_long(res)
        })
    }

    pub fn decrypt_update(&self, session: sys::CK_SESSION_HANDLE,
                          encrypted_part: &[u8], part: Option<&mut [u8]>)
                          -> Result<usize> {
        Ok(unsafe {
            let mut res = opt_len(&part);
            call_ck!(self.C_DecryptUpdate(session, encrypted_part.as_ptr(),
                                          ck_len(encrypted_part),
                                          opt_mut_ptr(part), &mut res));
            from_ck_long(res)
        })
    }

    pub fn decrypt_final(&self, session: sys::CK_SESSION_HANDLE,
                         last_part: Option<&mut [u8]>) -> Result<usize> {
        Ok(unsafe {
            let mut res = opt_len(&last_part);
            call_ck!(self.C_DecryptFinal(session, opt_mut_ptr(last_part),
                                         &mut res));
            from_ck_long(res)
        })
    }

    pub fn digest_init(&self, session: sys::CK_SESSION_HANDLE,
                       mechanism: &sys::CK_MECHANISM) -> Result<()> {
        Ok(unsafe {
            call_ck!(self.C_DigestInit(session, mechanism))
        })
    }

    pub fn digest(&self, session: sys::CK_SESSION_HANDLE,
                  data: &[u8], digest: Option<&mut [u8]>) -> Result<usize> {
        Ok(unsafe {
            let mut res = opt_len(&digest);
            call_ck!(self.C_Digest(session, data.as_ptr(), ck_len(data),
                                   opt_mut_ptr(digest), &mut res));
            from_ck_long(res)
        })
    }

    pub fn digest_update(&self, session: sys::CK_SESSION_HANDLE,
                         part: &[u8]) -> Result<()> {
        Ok(unsafe {
            call_ck!(self.C_DigestUpdate(session, part.as_ptr(),
                                         ck_len(part)))
        })
    }

    pub fn digest_key(&self, session: sys::CK_SESSION_HANDLE,
                      key: sys::CK_OBJECT_HANDLE) -> Result<()> {
        Ok(unsafe { call_ck!(self.C_DigestKey(session, key)) })
    }

    pub fn digest_final(&self, session: sys::CK_SESSION_HANDLE,
                        digest: Option<&mut [u8]>) -> Result<usize> {
        Ok(unsafe {
            let mut res = opt_len(&digest);
            call_ck!(self.C_DigestFinal(session, opt_mut_ptr(digest),
                                        &mut res));
            from_ck_long(res)
        })
    }

    pub fn sign_init(&self, session: sys::CK_SESSION_HANDLE,
                     mechanism: &sys::CK_MECHANISM,
                     key: sys::CK_OBJECT_HANDLE) -> Result<()> {
        Ok(unsafe { call_ck!(self.C_SignInit(session, mechanism, key)) })
    }

    pub fn sign(&self, session: sys::CK_SESSION_HANDLE,
                data: &[u8], signature: Option<&mut [u8]>) -> Result<usize> {
        Ok(unsafe {
            let mut res = opt_len(&signature);
            call_ck!(self.C_Sign(session, data.as_ptr(), ck_len(data),
                                 opt_mut_ptr(signature), &mut res));
            from_ck_long(res)
        })
    }

    pub fn sign_update(&self, session: sys::CK_SESSION_HANDLE,
                       part: &[u8]) -> Result<()> {
        Ok(unsafe {
            call_ck!(self.C_SignUpdate(session, part.as_ptr(), ck_len(part)));
        })
    }

    pub fn sign_final(&self, session: sys::CK_SESSION_HANDLE,
                      signature: Option<&mut [u8]>) -> Result<usize> {
        Ok(unsafe {
            let mut res = opt_len(&signature);
            call_ck!(self.C_SignFinal(session, opt_mut_ptr(signature),
                                      &mut res));
            from_ck_long(res)
        })
    }

    pub fn sign_recover_init(&self, session: sys::CK_SESSION_HANDLE,
                             mechanism: &sys::CK_MECHANISM,
                             key: sys::CK_OBJECT_HANDLE) -> Result<()> {
        Ok(unsafe {
            call_ck!(self.C_SignRecoverInit(session, mechanism, key))
        })
    }

    pub fn sign_recover(&self, session: sys::CK_SESSION_HANDLE,
                        data: &[u8], signature: Option<&mut [u8]>)
                        -> Result<usize> {
        Ok(unsafe {
            let mut res = opt_len(&signature);
            call_ck!(self.C_SignRecover(session, data.as_ptr(), ck_len(data),
                                        opt_mut_ptr(signature), &mut res));
            from_ck_long(res)
        })
    }

    pub fn verify_init(&self, session: sys::CK_SESSION_HANDLE,
                       mechanism: &sys::CK_MECHANISM,
                       key: sys::CK_OBJECT_HANDLE) -> Result<()> {
        Ok(unsafe {
            call_ck!(self.C_VerifyInit(session, mechanism, key))
        })
    }

    pub fn verify(&self, session: sys::CK_SESSION_HANDLE,
                  data: &[u8], signature: &[u8]) -> Result<()> {
        Ok(unsafe {
            call_ck!(self.C_Verify(session, data.as_ptr(), ck_len(data),
                                   signature.as_ptr(), ck_len(signature)))
        })
    }
                                        
    pub fn verify_update(&self, session: sys::CK_SESSION_HANDLE,
                         data: &[u8]) -> Result<()> {
        Ok(unsafe {
            call_ck!(self.C_VerifyUpdate(session, data.as_ptr(), ck_len(data)))
        })
    }

    pub fn verify_final(&self, session: sys::CK_SESSION_HANDLE,
                        signature: &[u8]) -> Result<()> {
        Ok(unsafe {
            call_ck!(self.C_VerifyFinal(session, signature.as_ptr(),
                                        ck_len(signature)))
        })
    }

    pub fn verify_recover_init(&self, session: sys::CK_SESSION_HANDLE,
                               mechanism: &sys::CK_MECHANISM,
                               key: sys::CK_OBJECT_HANDLE) -> Result<()> {
        Ok(unsafe {
            call_ck!(self.C_VerifyRecoverInit(session, mechanism, key))
        })
    }

    pub fn verify_recover(&self, session: sys::CK_SESSION_HANDLE,
                          signature: &[u8], data: Option<&mut [u8]>)
                          -> Result<usize> {
        Ok(unsafe {
            let mut res = opt_len(&data);
            call_ck!(self.C_VerifyRecover(session, signature.as_ptr(),
                                          ck_len(signature),
                                          opt_mut_ptr(data), &mut res));
            from_ck_long(res)
        })
    }

    pub fn digest_encrypt_update(&self, session: sys::CK_SESSION_HANDLE,
                                 part: &[u8],
                                 encrypted_part: Option<&mut [u8]>)
                                 -> Result<usize> {
        Ok(unsafe {
            let mut res = opt_len(&encrypted_part);
            call_ck!(self.C_DigestEncryptUpdate(session, part.as_ptr(),
                                                ck_len(part),
                                                opt_mut_ptr(encrypted_part),
                                                &mut res));
            from_ck_long(res)
        })
    }

    pub fn decrypt_digest_update(&self, session: sys::CK_SESSION_HANDLE,
                                 encrypted_part: &[u8],
                                 part: Option<&mut [u8]>) -> Result<usize> {
        Ok(unsafe {
            let mut res = opt_len(&part);
            call_ck!(self.C_DecryptDigestUpdate(session,
                                                encrypted_part.as_ptr(),
                                                ck_len(encrypted_part),
                                                opt_mut_ptr(part), &mut res));
            from_ck_long(res)
        })
    }

    pub fn sign_encrypt_update(&self, session: sys::CK_SESSION_HANDLE,
                               part: &[u8],
                               encrypted_part: Option<&mut [u8]>)
                               -> Result<usize> {
        Ok(unsafe {
            let mut res = opt_len(&encrypted_part);
            call_ck!(self.C_SignEncryptUpdate(session, part.as_ptr(),
                                              ck_len(part),
                                              opt_mut_ptr(encrypted_part),
                                              &mut res));
            from_ck_long(res)
        })
    }

    pub fn decrypt_verify_update(&self, session: sys::CK_SESSION_HANDLE,
                                 encrypted_part: &[u8],
                                 part: Option<&mut [u8]>) -> Result<usize> {
        Ok(unsafe {
            let mut res = opt_len(&part);
            call_ck!(self.C_DecryptVerifyUpdate(session,
                                                encrypted_part.as_ptr(),
                                                ck_len(encrypted_part),
                                                opt_mut_ptr(part), &mut res));
            from_ck_long(res)
        })
    }

    pub fn generate_key<'a, T>(&self, session: sys::CK_SESSION_HANDLE,
                               mechanism: &sys::CK_MECHANISM, template: T)
                               -> Result<sys::CK_OBJECT_HANDLE>
                        where T: AsRef<[Attribute<'a>]> {
        Ok(unsafe {
            let mut res = 0;
            let (ptr, len) = translate_template(template);
            call_ck!(self.C_GenerateKey(session, mechanism, ptr, len,
                                        &mut res));
            res
        })
    }

    /// Returns (public, private).
    pub fn generate_key_pair<'a, T, U>(&self, session: sys::CK_SESSION_HANDLE,
                                       mechanism: &sys::CK_MECHANISM,
                                       public_key_template: T,
                                       private_key_template: U)
                                       -> Result<(sys::CK_OBJECT_HANDLE,
                                                  sys::CK_OBJECT_HANDLE)>
                             where T: AsRef<[Attribute<'a>]>,
                                   U: AsRef<[Attribute<'a>]> {
        Ok(unsafe {
            let mut res = (0, 0);
            let (pub_ptr, pub_len) = translate_template(public_key_template);
            let (prv_ptr, prv_len) = translate_template(private_key_template);
            call_ck!(self.C_GenerateKeyPair(session, mechanism,
                                            pub_ptr, pub_len,
                                            prv_ptr, prv_len,
                                            &mut res.0, &mut res.1));
            res
        })
    }

    pub fn wrap_key(&self, session: sys::CK_SESSION_HANDLE,
                    mechanism: &sys::CK_MECHANISM,
                    wrapping_key: sys::CK_OBJECT_HANDLE,
                    key: sys::CK_OBJECT_HANDLE,
                    wrapped_key: Option<&mut [u8]>) -> Result<usize> {
        Ok(unsafe {
            let mut res = opt_len(&wrapped_key);
            call_ck!(self.C_WrapKey(session, mechanism, wrapping_key, key,
                                    opt_mut_ptr(wrapped_key), &mut res));
            from_ck_long(res)
        })
    }

    pub fn unwrap_key<'a, T>(&self, session: sys::CK_SESSION_HANDLE,
                             mechanism: &sys::CK_MECHANISM,
                             unwrapping_key: sys::CK_OBJECT_HANDLE,
                             wrapped_key: &[u8], template: T)
                             -> Result<sys::CK_OBJECT_HANDLE>
                      where T: AsRef<[Attribute<'a>]> {
        Ok(unsafe {
            let mut res = 0;
            let (ptr, len) = translate_template(template);
            call_ck!(self.C_UnwrapKey(session, mechanism, unwrapping_key,
                                      wrapped_key.as_ptr(),
                                      ck_len(wrapped_key), ptr, len,
                                      &mut res));
            res
        })
    }

    pub fn derive_key<'a, T>(&self, session: sys::CK_SESSION_HANDLE,
                             mechanism: &sys::CK_MECHANISM,
                             base_key: sys::CK_OBJECT_HANDLE, template: T)
                             -> Result<sys::CK_OBJECT_HANDLE>
                      where T: AsRef<[Attribute<'a>]> {
        Ok(unsafe {
            let mut res = 0;
            let (ptr, len) = translate_template(template);
            call_ck!(self.C_DeriveKey(session, mechanism, base_key,
                                      ptr, len, &mut res));
            res
        })
    }

    pub fn seed_random(&self, session: sys::CK_SESSION_HANDLE, seed: &[u8])
                       -> Result<()> {
        Ok(unsafe {
            call_ck!(self.C_SeedRandom(session, seed.as_ptr(), ck_len(seed)))
        })
    }

    pub fn generate_random(&self, session: sys::CK_SESSION_HANDLE,
                           random_data: &mut [u8]) -> Result<()> {
        Ok(unsafe {
            call_ck!(self.C_GenerateRandom(session, random_data.as_mut_ptr(),
                                           ck_len(random_data)))
        })
    }
}

fn ck_len<T, R: AsRef<[T]>>(r: R) -> sys::CK_ULONG {
    to_ck_long(r.as_ref().len())
}


/// Converts a `usize` to a `CK_ULONG`.
///
/// # Panics 
///
/// On some targets (such as 64 bit Windows), `CK_ULONG` is 32 bits while
/// `usize` is 64 bits. On these systems, the function will panic if given
/// a value that is too large.
#[inline(always)]
pub fn to_ck_long(x: usize) -> sys::CK_ULONG {
    // XXX Does this get optimized away if both types are identical?
    assert!(x <= sys::CK_ULONG_MAX as usize);
    x as sys::CK_ULONG
}

/// Converts a `CK_ULONG` into a `usize`.
///
/// # Assumption
///
/// Since `CK_ULONG` is equal to C’s `unsigned long int`, it should never
/// be bigger than the target’s pointer size and a cast should be safe.
#[inline(always)]
pub fn from_ck_long(x: sys::CK_ULONG) -> usize {
    x as usize
}

unsafe fn ck_void_ptr<T, R: AsRef<[T]>>(r: R) -> *const sys::CK_VOID {
    r.as_ref().as_ptr() as *const _
}

fn opt_len<T, R: AsRef<[T]>>(r: &Option<R>) -> sys::CK_ULONG {
    match *r {
        Some(ref r) => ck_len(r.as_ref()),
        None => 0
    }
}

fn opt_ptr<T, R: AsRef<[T]>>(r: &Option<R>) -> *const T {
    match *r {
        Some(ref r) => r.as_ref().as_ptr(),
        None => ptr::null()
    }
}
    
fn opt_mut_ptr<T, R: AsMut<[T]>>(r: Option<R>) -> *mut T {
    match r {
        Some(mut r) => r.as_mut().as_mut_ptr(),
        None => ptr::null_mut()
    }
}

unsafe fn translate_template<'a, T>(t: T) -> (*const sys::CK_ATTRIBUTE,
                                              sys::CK_ULONG)
                             where T: AsRef<[Attribute<'a>]> {
    let template: &[sys::CK_ATTRIBUTE] = mem::transmute(t.as_ref());
    (template.as_ptr(), ck_len(template))
}


//------------ Attribute ----------------------------------------------------

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


