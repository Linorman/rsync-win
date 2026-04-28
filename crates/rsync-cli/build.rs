fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        embed_manifest::embed_manifest(
            embed_manifest::new_manifest("rsync-win")
                .long_path_aware(embed_manifest::manifest::Setting::Enabled),
        )
        .expect("unable to embed Windows application manifest");
    }
}
