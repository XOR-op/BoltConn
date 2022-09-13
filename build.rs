extern crate cc;
extern crate core;

fn main() {
    if cfg!(target_os = "macos") {
        cc::Build::new()
            .file("src/iface/macos/tun.c")
            .warnings(true)
            .compile("tun")
    } else if cfg!(target_os = "linux") {
        cc::Build::new()
            .file("src/iface/linux/tun.c")
            .warnings(true)
            .compile("tun")
    } else {
        panic!("Platform not supported!");
    }
}
