#![no_std]
#![doc = include_str!("../README.md")]

extern crate alloc;

/// Internal structures and types for spoof configuration.
mod data;

// Core logic implementing spoofing routines.
mod uwd;
pub use uwd::*;
