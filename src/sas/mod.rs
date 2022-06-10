#[cfg(unix)]
pub mod unix;
#[cfg(unix)]
pub use self::unix::*;
#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
pub use self::windows::*;