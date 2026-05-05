fn main() {
    match rsync_cli::run_from_env_main() {
        Ok(()) => {}
        Err(err) => {
            let code = rsync_cli::output::exit_code_from_error(&err);
            eprintln!("rsync-win: {err:#}");
            std::process::exit(code);
        }
    }
}
