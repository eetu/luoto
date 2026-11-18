//! The picture that opens `luoto setup`: none yet.

/// Run `work` behind a spinner named `label`, then print what `lines` says of what it found.
pub fn during<T: Send>(
    label: &str,
    work: impl FnOnce() -> T + Send,
    lines: impl FnOnce(&T) -> Vec<String> + Send,
) -> T {
    let found = crate::progress::wait(label, work);
    for line in lines(&found) {
        println!("{line}");
    }
    found
}
