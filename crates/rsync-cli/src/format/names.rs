use super::prelude::*;
pub(crate) fn format_bytes(bytes: u64) -> String {
    output::format_bytes_human(bytes)
}

pub(crate) fn transfer_rate_label(bytes: u64, elapsed: Duration) -> String {
    output::transfer_rate_label(bytes, elapsed)
}

pub(crate) fn output_name(path: &Path, eight_bit_output: bool) -> String {
    let display_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    output::escape_output_name(&display_name, eight_bit_output)
}
