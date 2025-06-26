#![no_std]
#![allow(clippy::doc_overindented_list_items)]
#![doc = include_str!("../README.md")]

extern crate alloc;

mod data;

// Core logic implementing spoofing routines.
mod uwd;
pub use uwd::*;
