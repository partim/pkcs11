
use std::{mem, ptr, slice};
use std::marker::PhantomData;
use pkcs11_sys as sys;
use super::{from_ck_long, to_ck_long};


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



