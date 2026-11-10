//! Print the metadata lsdk reads from an app ELF: `cargo run --example elfinfo --features loader -- app.elf`
fn main() {
    let path = std::env::args().nth(1).expect("usage: elfinfo <app.elf>");
    let data = std::fs::read(&path).expect("read");
    match lsdk::loader::AppImage::from_elf(&data) {
        Ok(img) => {
            println!(
                "name {} version {:?} api {:?} flags 0x{:x} target {:?} data {} params {} entry 0x{:x}",
                img.name,
                img.version,
                img.api_level,
                img.flags,
                img.target_id.map(|t| format!("0x{t:08x}")),
                img.data_size,
                img.install_params_size,
                img.entry
            );
            for a in &img.areas {
                println!("area 0x{:08x} len {}", a.address, a.data.len());
            }
            println!("code length {:?}", img.code_length());
            if let Some(t) = img.target_id {
                println!(
                    "app hash {}",
                    hex::encode(img.app_hash(t).unwrap_or_default())
                );
            }
            println!(
                "create_app params {}",
                hex::encode(img.create_app_params().unwrap_or_default())
            );
        }
        Err(e) => eprintln!("error: {e}"),
    }
}
