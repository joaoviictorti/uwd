#![no_std]
#![doc = include_str!("../README.md")]

extern crate alloc;

/// Internal structures and types for spoof configuration.
mod data;

/// Helper functions used internally.
mod utils;

// Core logic implementing spoofing routines.
mod uwd;
pub use uwd::*;
