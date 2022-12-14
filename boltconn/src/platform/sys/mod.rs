#[cfg(target_os = "macos")]
pub mod macos_ffi;
#[cfg(target_os = "macos")]
mod macos_sys;

#[cfg(target_os = "macos")]
pub use macos_sys::*;

#[cfg(target_os = "macos")]
pub use macos_ffi as ffi;

#[cfg(target_os = "linux")]
pub mod linux_ffi;
#[cfg(target_os = "linux")]
mod linux_sys;

#[cfg(target_os = "linux")]
pub use linux_ffi as ffi;
#[cfg(target_os = "linux")]
pub use linux_sys::*;
