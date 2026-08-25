fn main() {
    println!("cargo:rerun-if-changed=native/common.h");
    println!("cargo:rerun-if-changed=native/encryption_internal.h");
    println!("cargo:rerun-if-changed=native/file_utils.h");
    println!("cargo:rerun-if-changed=native/signal_utils.h");
    println!("cargo:rerun-if-changed=native/reddit_steg.h");
    println!("cargo:rerun-if-changed=native/reddit_steg.cpp");
    println!("cargo:rerun-if-changed=native/reddit_bridge.cpp");

    cc::Build::new()
        .cpp(true)
        .file("native/reddit_steg.cpp")
        .file("native/reddit_bridge.cpp")
        .include("native")
        .flag_if_supported("-std=c++20")
        .flag_if_supported("-Wall")
        .flag_if_supported("-Wextra")
        .flag_if_supported("-Wpedantic")
        .compile("jdvrif_reddit");

    println!("cargo:rustc-link-lib=jpeg");
}
