fn main() {
    println!("cargo:rerun-if-changed=src/common.h");
    println!("cargo:rerun-if-changed=src/encryption_internal.h");
    println!("cargo:rerun-if-changed=src/file_utils.h");
    println!("cargo:rerun-if-changed=src/signal_utils.h");
    println!("cargo:rerun-if-changed=src/reddit_steg.h");
    println!("cargo:rerun-if-changed=src/reddit_steg.cpp");
    println!("cargo:rerun-if-changed=src/reddit_bridge.cpp");

    cc::Build::new()
        .cpp(true)
        .file("src/reddit_steg.cpp")
        .file("src/reddit_bridge.cpp")
        .include("src")
        .flag_if_supported("-std=c++20")
        .flag_if_supported("-Wall")
        .flag_if_supported("-Wextra")
        .flag_if_supported("-Wpedantic")
        .compile("jdvrif_reddit");

    println!("cargo:rustc-link-lib=jpeg");
}
