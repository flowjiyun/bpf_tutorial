#![no_std]

const MAX_PATH_LEN: usize = 256;
const TASK_NAME_LEN: usize = 16;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Event {
    pub uid: u32,
    pub pid: u32,
    pub task_name: [u8; TASK_NAME_LEN],
    pub file_path: [u8; MAX_PATH_LEN],
}