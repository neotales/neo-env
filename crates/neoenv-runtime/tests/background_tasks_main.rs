#[cfg(unix)]
#[path = "background_tasks.rs"]
mod background_tasks;

#[cfg(unix)]
fn main() {
    background_tasks::main();
}

#[cfg(not(any(unix, windows)))]
fn main() {}

#[cfg(windows)]
#[path = "background_tasks_windows.rs"]
mod windows;
#[cfg(windows)]
fn main() {
    windows::main();
}
