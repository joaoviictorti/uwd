use std::env;

fn main() {
    if env::var("DOCS_RS").is_ok() {
        println!("cargo:warning=Skipping ASM build for docs.rs");
        return;
    }

    let target = env::var("TARGET").expect("Missing TARGET environment variable");
    let out_dir = env::var("OUT_DIR").expect("Missing OUT_DIR environment variable");

    // Supports x86_64 environments only
    if !target.contains("x86_64") {
        panic!("This build script only supports x86_64 targets.");
    }

    if target.contains("msvc") {
        // Use MASM with cc
        cc::Build::new()
            .file("src/asm/msvc/desync.asm")
            .file("src/asm/msvc/synthetic.asm")
            .compile("spoof");
    } else if target.contains("gnu") {
        // Use NASM with nasm_rs
        let sources = [
            "src/asm/gnu/desync.asm",
            "src/asm/gnu/synthetic.asm",
        ];
        
        if let Err(e) = nasm_rs::compile_library("spoof", &sources) {
            panic!("Failed to compile with NASM [spoof]: {}", e);
        }
        
        for source in &sources {
            println!("cargo:rerun-if-changed={}", source);
        }
        
        println!("cargo:rustc-link-search=native={}", out_dir);
        println!("cargo:rustc-link-lib=static=spoof");
    } else {
        panic!("Unsupported target: {}", target);
    }
}
