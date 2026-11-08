fn main() {
    println!("cargo:rerun-if-env-changed=PMASK_BUILD_COMMIT");
    let commit = std::env::var("PMASK_BUILD_COMMIT").unwrap_or_else(|_| "unknown".into());
    println!("cargo:rustc-env=PMASK_BUILD_COMMIT={commit}");
}
