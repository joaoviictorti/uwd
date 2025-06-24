#![no_std]
#![warn(clippy::all)]
#![doc = include_str!("../README.md")]

extern crate alloc;

mod data;

// Core logic implementing spoofing routines.
mod uwd;
pub use uwd::*;
