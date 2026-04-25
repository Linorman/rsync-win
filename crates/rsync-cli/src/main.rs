use anyhow::Result;

fn main() -> Result<()> {
    rsync_cli::run_from_env()
}
