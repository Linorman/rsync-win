use super::prelude::*;
pub(crate) fn read_local_file(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(to_long_path_safe(path))
        .with_context(|| format!("failed to read {}", path.display()))
}

pub(crate) fn open_local_file(path: &Path) -> Result<File> {
    File::open(to_long_path_safe(path))
        .with_context(|| format!("failed to open {}", path.display()))
}

pub(crate) fn create_local_file(path: &Path) -> Result<File> {
    File::create(to_long_path_safe(path))
        .with_context(|| format!("failed to create {}", path.display()))
}

pub(crate) fn create_local_dir_all(path: &Path) -> Result<()> {
    std::fs::create_dir_all(to_long_path_safe(path))
        .with_context(|| format!("failed to create {}", path.display()))
}

pub(crate) fn remove_local_file_best_effort(path: &Path) {
    let _ = std::fs::remove_file(to_long_path_safe(path));
}

pub(crate) fn receive_temp_path(target: &Path) -> PathBuf {
    let file_name = target
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_else(|| "rsync-win".into());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let temp_name = format!(".{file_name}.{}.{}.recv", std::process::id(), nanos);
    target
        .parent()
        .map(|parent| parent.join(&temp_name))
        .unwrap_or_else(|| PathBuf::from(temp_name))
}
