fn main() {
    println!("cargo:rerun-if-changed=src/common.h");
    println!("cargo:rerun-if-changed=src/encryption_internal.h");
    println!("cargo:rerun-if-changed=src/file_utils.h");
    println!("cargo:rerun-if-changed=src/signal_utils.h");
    println!("cargo:rerun-if-changed=src/reddit_steg.h");
    println!("cargo:rerun-if-changed=src/reddit_steg.cpp");
    println!("cargo:rerun-if-changed=src/reddit_bridge.cpp");
    println!("cargo:rerun-if-changed=src/twitter_jpeg_codec.h");
    println!("cargo:rerun-if-changed=src/twitter_jpeg_codec.cpp");
    println!("cargo:rerun-if-changed=src/twitter_juniward.h");
    println!("cargo:rerun-if-changed=src/twitter_juniward.cpp");
    println!("cargo:rerun-if-changed=src/twitter_stc.h");
    println!("cargo:rerun-if-changed=src/twitter_stc.cpp");
    println!("cargo:rerun-if-changed=src/twitter_steg.h");
    println!("cargo:rerun-if-changed=src/twitter_steg.cpp");
    println!("cargo:rerun-if-changed=src/twitter_bridge.cpp");

    let mut build = cc::Build::new();
    build
        .cpp(true)
        .file("src/reddit_steg.cpp")
        .file("src/reddit_bridge.cpp")
        .file("src/twitter_jpeg_codec.cpp")
        .file("src/twitter_juniward.cpp")
        .file("src/twitter_stc.cpp")
        .file("src/twitter_steg.cpp")
        .file("src/twitter_bridge.cpp")
        .include("src")
        .flag_if_supported("-std=c++20")
        .flag_if_supported("-Wall")
        .flag_if_supported("-Wextra")
        .flag_if_supported("-Wpedantic");

    // Match the native build's parallel J-UNIWARD cost calculation when GCC
    // is in use. Clang remains fully supported through the sequential fallback
    // unless its platform supplies and configures libomp independently.
    let compiler = build.get_compiler();
    if compiler.is_like_gnu() && !compiler.is_like_clang() {
        build.flag("-fopenmp");
        println!("cargo:rustc-link-lib=gomp");
    }

    build.compile("jdvrif_carriers");

    println!("cargo:rustc-link-lib=jpeg");
}
