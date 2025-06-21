use std::env::var;
use std::fs::{create_dir_all, remove_file, File};
use std::path::PathBuf;

use reqwest::blocking::get;
use zip::read::root_dir_common_filter;
use zip::ZipArchive;

const WINDIVERT_VERSION: &str = "2.2.2";

fn main() {
    let windivert_archive = format!("WinDivert-{WINDIVERT_VERSION}-A.zip");
    let manifest_dir = PathBuf::from(var("CARGO_MANIFEST_DIR").unwrap());
    let windivert_binaries_local_path = manifest_dir.join("windivert_binaries");
    let windivert_archive_path = manifest_dir.join(&windivert_archive);

    let local_dll_src_path = windivert_binaries_local_path.join(format!("x86/WinDivert.dll"));
    let local_sys_src_path_64 = windivert_binaries_local_path.join(format!("x86/WinDivert{}.sys", WINDIVERT_VERSION.replace(".", "")));
    let local_sys_src_path_32 = windivert_binaries_local_path.join(format!("x86/WinDivert{}.sys", WINDIVERT_VERSION.replace(".", "")));

    let required_files_exist = local_dll_src_path.exists() && local_sys_src_path_64.exists() && local_sys_src_path_32.exists();
    if !required_files_exist {
        println!("WinDivert binaries not found in 'windivert_binaries/'. Attempting to download...");
        create_dir_all(&windivert_binaries_local_path).expect("Failed to create windivert_binaries directory");

        let windivert_download_url = format!("https://github.com/basil00/WinDivert/releases/download/v{WINDIVERT_VERSION}/{windivert_archive}");
        println!("Downloading WinDivert from {}", windivert_download_url);
        let mut response = get(windivert_download_url).expect("Failed to download WinDivert archive");

        let mut file = File::create(&windivert_archive_path).expect("Failed to create WinDivert archive file");
        response.copy_to(&mut file).expect("Failed to write WinDivert archive to file");
        println!("Downloaded WinDivert to {}", windivert_archive_path.display());

        let file = File::open(&windivert_archive_path).expect("Failed to open WinDivert archive for extraction");
        let mut archive = ZipArchive::new(file).expect("Failed to create zip archive");
        archive.extract_unwrapped_root_dir(&windivert_binaries_local_path, root_dir_common_filter).expect("Error etracting WinDiert archive!");
        println!("Extracted WinDivert archive to {}", windivert_binaries_local_path.display());

        remove_file(&windivert_archive_path).expect("Failed to remove downloaded WinDivert archive");
        println!("Removed downloaded archive {}", windivert_archive_path.display());
     } else {
        println!("WinDivert binaries found locally in 'windivert_binaries/'.");
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}/", windivert_binaries_local_path.display());
}
