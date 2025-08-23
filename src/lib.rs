#![no_std]
#![allow(clippy::doc_overindented_list_items)]
#![doc = include_str!("../README.md")]

extern crate alloc;

mod data;
mod uwd;

pub use uwd::*;