#![no_std]
#![doc = include_str!("../README.md")]
#![allow(
    clippy::doc_overindented_list_items,
    clippy::collapsible_if
)]

extern crate alloc;

mod data;
mod uwd;

pub use uwd::*;
