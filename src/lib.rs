#![no_std]
#![doc = include_str!("../README.md")]
#![allow(clippy::collapsible_if)]

extern crate alloc;

mod data;
mod uwd;

pub use uwd::*;
