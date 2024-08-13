#![no_std]

#[cfg(feature = "user")]
use aya::Pod;

#[repr(C)]
#[derive(Debug, Clone, Copy)]

pub struct FileOpenInfo {
    pub count: u64,
}

#[cfg(feature = "user")]
unsafe impl Pod for FileOpenInfo {}