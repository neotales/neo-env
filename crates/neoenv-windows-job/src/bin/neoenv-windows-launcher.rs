//! Dedicated private launcher. No application threads are started before it.

#[cfg(windows)]
#[path = "../protocol.rs"]
mod protocol;
#[cfg(windows)]
#[path = "../windows.rs"]
#[allow(dead_code, unused_imports)] // The private binary shares types with the public adapter.
mod windows;

#[cfg(windows)]
fn main() {
    let result = (|| {
        let mut args: Vec<_> = std::env::args_os().skip(1).collect();
        let proxy = args.first().is_some_and(|arg| arg == "--proxy");
        let forward = args.first().is_some_and(|arg| arg == "--forward-proxy");
        if proxy || forward {
            args.remove(0);
        }
        if args.len() != 3 {
            return Err(());
        }
        let name = args[0].to_str().ok_or(())?;
        let pid = args[1].to_str().ok_or(())?.parse().map_err(|_| ())?;
        let creation_time = args[2].to_str().ok_or(())?.parse().map_err(|_| ())?;
        let identity = windows::HostIdentity { pid, creation_time };
        if forward {
            windows::proxy::run_forward_proxy(name, identity).map_err(|_| ())
        } else if proxy {
            windows::proxy::run_proxy(name, identity).map_err(|_| ())
        } else {
            windows::launcher::run_launcher(name, identity).map_err(|_| ())
        }
    })();
    std::process::exit(i32::from(result.is_err()));
}

#[cfg(not(windows))]
fn main() {}
