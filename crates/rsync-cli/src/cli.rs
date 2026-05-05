use std::path::PathBuf;

use clap::{ArgAction, Parser, ValueEnum};
use rsync_core::MetadataPolicy;
use rsync_fs::DeleteMode;
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CliMetadataPolicy {
    Portable,
    Posix,
    NtfsNative,
}

impl From<CliMetadataPolicy> for MetadataPolicy {
    fn from(value: CliMetadataPolicy) -> Self {
        match value {
            CliMetadataPolicy::Portable => Self::Portable,
            CliMetadataPolicy::Posix => Self::Posix,
            CliMetadataPolicy::NtfsNative => Self::NtfsNative,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "rsync-win",
    disable_version_flag = true,
    about = "Native Windows rsync development build",
    long_about = "Native Windows rsync development build.\n\nThis build executes local portable syncs and an experimental remote-shell MVP for ordinary files/directories using rsync protocol 31 against modern peers, with protocol 27 compatibility code retained for fallback work."
)]
pub struct Cli {
    #[arg(short = 'V', long, action = ArgAction::SetTrue, help = "Print version")]
    pub(crate) version: bool,

    #[arg(long, help = "Print the supported rsync protocol version range")]
    pub(crate) protocol_range: bool,

    #[arg(long, action = ArgAction::SetTrue, help = "Print the transfer plan without executing it")]
    pub(crate) plan: bool,

    #[arg(short = 'r', long, action = ArgAction::SetTrue, help = "Recurse into directories")]
    pub(crate) recursive: bool,

    #[arg(skip)]
    pub(crate) no_recursive: bool,

    #[arg(long = "inc-recursive", visible_alias = "i-r", action = ArgAction::SetTrue, help = "Use upstream protocol-31 incremental recursion for remote recursive transfers")]
    pub(crate) inc_recursive: bool,

    #[arg(long = "no-inc-recursive", visible_alias = "no-i-r", action = ArgAction::SetTrue, help = "Disable upstream incremental recursion for remote recursive transfers")]
    pub(crate) no_inc_recursive: bool,

    #[arg(short = 't', long = "times", action = ArgAction::SetTrue, help = "Preserve modification times")]
    pub(crate) preserve_times: bool,

    #[arg(skip)]
    pub(crate) no_times: bool,

    #[arg(short = 'a', long = "archive", action = ArgAction::SetTrue, help = "Enable archive mode as -rlptgoD, with unsupported metadata reported")]
    pub(crate) archive: bool,

    #[arg(short = 'n', long = "dry-run", action = ArgAction::SetTrue, help = "Plan actions without writing or deleting")]
    pub(crate) dry_run: bool,

    #[arg(long, action = ArgAction::SetTrue, help = "Delete receiver files that are not present on sender")]
    pub(crate) delete: bool,

    #[arg(skip)]
    pub(crate) delete_mode: DeleteMode,

    #[arg(long = "whole-file", action = ArgAction::SetTrue, help = "Use whole-file transfer planning")]
    pub(crate) whole_file: bool,

    #[arg(short = 'z', long = "compress", action = ArgAction::SetTrue, help = "Enable negotiated rsync compression where the active transfer mode supports it")]
    pub(crate) compress: bool,

    #[arg(skip)]
    pub(crate) compress_choice: Option<String>,

    #[arg(skip)]
    pub(crate) compress_level: Option<u32>,

    #[arg(skip)]
    pub(crate) compress_threads: Option<usize>,

    #[arg(skip)]
    pub(crate) skip_compress: Vec<String>,

    #[arg(skip)]
    pub(crate) quiet: u8,

    #[arg(skip)]
    pub(crate) info_flags: Vec<String>,

    #[arg(skip)]
    pub(crate) debug_flags: Vec<String>,

    #[arg(skip)]
    pub(crate) msgs2stderr: bool,

    #[arg(skip)]
    pub(crate) no_msgs2stderr: bool,

    #[arg(skip)]
    pub(crate) stderr_mode: Option<String>,

    #[arg(skip)]
    pub(crate) out_format: Option<String>,

    #[arg(skip)]
    pub(crate) eight_bit_output: bool,

    #[arg(skip)]
    pub(crate) client_log_file: Option<PathBuf>,

    #[arg(skip)]
    pub(crate) client_log_file_format: Option<String>,

    #[arg(skip)]
    pub(crate) human_readable: u8,

    #[arg(skip)]
    pub(crate) help: bool,

    #[arg(skip)]
    pub(crate) progress: bool,

    #[arg(skip)]
    pub(crate) relative: bool,

    #[arg(skip)]
    pub(crate) implied_dirs: bool,

    #[arg(skip)]
    pub(crate) transfer_dirs: bool,

    #[arg(skip)]
    pub(crate) mkpath: bool,

    #[arg(skip)]
    pub(crate) one_file_system: bool,

    #[arg(short = 'v', action = ArgAction::Count, help = "Increase verbosity")]
    pub(crate) verbosity: u8,

    #[arg(short = 'i', long = "itemize-changes", action = ArgAction::SetTrue, help = "Print rsync-style itemized changes")]
    pub(crate) itemize_changes: bool,

    #[arg(long = "stats", action = ArgAction::SetTrue, help = "Print structured transfer statistics")]
    pub(crate) stats: bool,

    #[arg(long = "list-only", action = ArgAction::SetTrue, help = "List daemon modules or remote entries without copying")]
    pub(crate) list_only: bool,

    #[arg(long = "metadata-policy", value_enum, default_value_t = CliMetadataPolicy::Portable, help = "Metadata compatibility policy")]
    pub(crate) metadata_policy: CliMetadataPolicy,

    #[arg(long, action = ArgAction::SetTrue, help = "Treat unsupported requested metadata as an error")]
    pub(crate) fail_on_metadata_loss: bool,

    #[arg(short = 'p', long = "perms", action = ArgAction::SetTrue, help = "Request POSIX permission preservation")]
    pub(crate) preserve_permissions: bool,

    #[arg(skip)]
    pub(crate) no_permissions: bool,

    #[arg(short = 'o', long = "owner", action = ArgAction::SetTrue, help = "Request POSIX owner preservation")]
    pub(crate) preserve_owner: bool,

    #[arg(short = 'g', long = "group", action = ArgAction::SetTrue, help = "Request POSIX group preservation")]
    pub(crate) preserve_group: bool,

    #[arg(long = "executability", action = ArgAction::SetTrue, help = "Preserve executable-ness where POSIX mode metadata is supported")]
    pub(crate) executability: bool,

    #[arg(long = "acls", action = ArgAction::SetTrue, help = "Request POSIX ACL preservation")]
    pub(crate) acls: bool,

    #[arg(long = "xattrs", action = ArgAction::SetTrue, help = "Request POSIX extended attribute preservation")]
    pub(crate) xattrs: bool,

    #[arg(long = "fake-super", action = ArgAction::SetTrue, help = "Request fake-super style metadata sidecar storage")]
    pub(crate) fake_super: bool,

    #[arg(skip)]
    pub(crate) atimes: bool,

    #[arg(skip)]
    pub(crate) crtimes: bool,

    #[arg(skip)]
    pub(crate) omit_dir_times: bool,

    #[arg(long = "omit-link-times", action = ArgAction::SetTrue, help = "Do not request symlink mtime preservation")]
    pub(crate) omit_link_times: bool,

    #[arg(long = "vss", action = ArgAction::SetTrue, help = "Request VSS snapshot source mode for ntfs-native transfers")]
    pub(crate) vss: bool,

    #[arg(skip)]
    pub(crate) daemon_server: bool,

    #[arg(skip)]
    pub(crate) daemon_config: Option<PathBuf>,

    #[arg(skip)]
    pub(crate) daemon_params: Vec<String>,

    #[arg(skip)]
    pub(crate) daemon_no_detach: bool,

    #[arg(skip)]
    pub(crate) daemon_address: Option<String>,

    #[arg(skip)]
    pub(crate) daemon_port: Option<u16>,

    #[arg(skip)]
    pub(crate) daemon_sockopts: Option<String>,

    #[arg(skip)]
    pub(crate) daemon_connect_timeout_secs: Option<u64>,

    #[arg(skip)]
    pub(crate) daemon_no_motd: bool,

    #[arg(skip)]
    pub(crate) daemon_log_file: Option<PathBuf>,

    #[arg(skip)]
    pub(crate) daemon_log_file_format: Option<String>,

    #[arg(skip)]
    pub(crate) daemon_bwlimit: Option<String>,

    #[arg(skip)]
    pub(crate) internal_server: bool,

    #[arg(skip)]
    pub(crate) internal_sender: bool,

    #[arg(long = "include", help = "Add an include filter pattern")]
    pub(crate) includes: Vec<String>,

    #[arg(long = "exclude", help = "Add an exclude filter pattern")]
    pub(crate) excludes: Vec<String>,

    #[arg(long = "filter", help = "Add an rsync-style filter rule")]
    pub(crate) filters: Vec<String>,

    #[arg(skip)]
    pub(crate) exclude_from: Vec<PathBuf>,

    #[arg(skip)]
    pub(crate) include_from: Vec<PathBuf>,

    #[arg(skip)]
    pub(crate) cvs_exclude: bool,

    #[arg(
        long = "files-from",
        help = "Read the source file list from a newline-delimited or --from0 file"
    )]
    pub(crate) files_from: Option<std::path::PathBuf>,

    #[arg(long = "from0", action = ArgAction::SetTrue, help = "Interpret files-from records as NUL-delimited")]
    pub(crate) from0: bool,

    #[arg(short = 'c', long = "checksum", action = ArgAction::SetTrue, help = "Plan checksum-based updates")]
    pub(crate) checksum: bool,

    #[arg(skip)]
    pub(crate) checksum_choice: Option<String>,

    #[arg(skip)]
    pub(crate) checksum_seed: Option<i32>,

    #[arg(long = "size-only", action = ArgAction::SetTrue, help = "Plan updates using file size only")]
    pub(crate) size_only: bool,

    #[arg(long = "ignore-times", action = ArgAction::SetTrue, help = "Ignore quick-check times during planning")]
    pub(crate) ignore_times: bool,

    #[arg(long = "partial", action = ArgAction::SetTrue, help = "Keep partial files during real transfer execution")]
    pub(crate) partial: bool,

    #[arg(
        long = "partial-dir",
        help = "Directory for partial files during real transfer execution"
    )]
    pub(crate) partial_dir: Option<String>,

    #[arg(long = "inplace", action = ArgAction::SetTrue, help = "Plan in-place updates")]
    pub(crate) inplace: bool,

    #[arg(long = "append-verify", action = ArgAction::SetTrue, help = "Plan append-verify updates")]
    pub(crate) append_verify: bool,

    #[arg(skip)]
    pub(crate) append: bool,

    #[arg(skip)]
    pub(crate) update: bool,

    #[arg(skip)]
    pub(crate) existing: bool,

    #[arg(skip)]
    pub(crate) ignore_existing: bool,

    #[arg(skip)]
    pub(crate) max_size: Option<u64>,

    #[arg(skip)]
    pub(crate) min_size: Option<u64>,

    #[arg(skip)]
    pub(crate) modify_window: i64,

    #[arg(skip)]
    pub(crate) ignore_missing_args: bool,

    #[arg(skip)]
    pub(crate) delete_missing_args: bool,

    #[arg(skip)]
    pub(crate) delete_excluded: bool,

    #[arg(skip)]
    pub(crate) ignore_errors: bool,

    #[arg(skip)]
    pub(crate) force: bool,

    #[arg(skip)]
    pub(crate) max_delete: Option<usize>,

    #[arg(skip)]
    pub(crate) backup: bool,

    #[arg(skip)]
    pub(crate) backup_dir: Option<String>,

    #[arg(skip)]
    pub(crate) suffix: Option<String>,

    #[arg(skip)]
    pub(crate) temp_dir: Option<String>,

    #[arg(skip)]
    pub(crate) delay_updates: bool,

    #[arg(skip)]
    pub(crate) fsync: bool,

    #[arg(long = "numeric-ids", action = ArgAction::SetTrue, help = "Use numeric owner/group ids when supported")]
    pub(crate) numeric_ids: bool,

    #[arg(skip)]
    pub(crate) user_maps: Vec<String>,

    #[arg(skip)]
    pub(crate) group_maps: Vec<String>,

    #[arg(skip)]
    pub(crate) chown: Option<String>,

    #[arg(long = "no-o", alias = "no-owner", action = ArgAction::SetTrue, help = "Disable owner preservation requested by archive mode")]
    pub(crate) no_owner: bool,

    #[arg(long = "no-g", alias = "no-group", action = ArgAction::SetTrue, help = "Disable group preservation requested by archive mode")]
    pub(crate) no_group: bool,

    #[arg(
        long = "chmod",
        help = "Requested chmod expression, reported until implemented"
    )]
    pub(crate) chmod: Option<String>,

    #[arg(
        short = 'e',
        long = "rsh",
        value_name = "COMMAND",
        help = "Specify the remote shell command, e.g. \"ssh -p 10080\""
    )]
    pub(crate) remote_shell: Option<String>,

    #[arg(
        long = "password-file",
        help = "Read rsync daemon password from a local file"
    )]
    pub(crate) password_file: Option<PathBuf>,

    #[arg(long = "copy-links", action = ArgAction::SetTrue, help = "Copy symlink referents")]
    pub(crate) copy_links: bool,

    #[arg(long = "safe-links", action = ArgAction::SetTrue, help = "Ignore unsafe symlinks")]
    pub(crate) safe_links: bool,

    #[arg(long = "copy-unsafe-links", action = ArgAction::SetTrue, help = "Copy unsafe symlink referents")]
    pub(crate) copy_unsafe_links: bool,

    #[arg(skip)]
    pub(crate) copy_dirlinks: bool,

    #[arg(skip)]
    pub(crate) keep_dirlinks: bool,

    #[arg(skip)]
    pub(crate) munge_links: bool,

    #[arg(skip)]
    pub(crate) links: bool,

    #[arg(skip)]
    pub(crate) no_links: bool,

    #[arg(skip)]
    pub(crate) hard_links: bool,

    #[arg(skip)]
    pub(crate) devices: bool,

    #[arg(skip)]
    pub(crate) specials: bool,

    #[arg(skip)]
    pub(crate) no_devices: bool,

    #[arg(skip)]
    pub(crate) no_specials: bool,

    #[arg(skip)]
    pub(crate) copy_devices: bool,

    #[arg(skip)]
    pub(crate) write_devices: bool,

    #[arg(skip)]
    pub(crate) block_size: Option<u64>,

    #[arg(skip)]
    pub(crate) remote_options: Vec<String>,

    #[arg(skip)]
    pub(crate) rsync_path: Option<String>,

    #[arg(skip)]
    pub(crate) blocking_io: bool,

    #[arg(skip)]
    pub(crate) old_args: bool,

    #[arg(skip)]
    pub(crate) secluded_args: bool,

    #[arg(skip)]
    pub(crate) trust_sender: bool,

    #[arg(skip)]
    pub(crate) ipv4: bool,

    #[arg(skip)]
    pub(crate) ipv6: bool,

    #[arg(skip)]
    pub(crate) accepted_unsupported_options: Vec<String>,

    // Chunk 12: Advanced Transfer Features
    #[arg(skip)]
    pub(crate) compare_dest: Vec<String>,
    #[arg(skip)]
    pub(crate) copy_dest: Vec<String>,
    #[arg(skip)]
    pub(crate) link_dest: Vec<String>,
    #[arg(skip)]
    pub(crate) sparse: bool,
    #[arg(skip)]
    pub(crate) preallocate: bool,
    #[arg(skip)]
    pub(crate) fuzzy: bool,
    #[arg(skip)]
    pub(crate) copy_as: Option<String>,
    #[arg(skip)]
    pub(crate) super_flag: bool,
    #[arg(skip)]
    pub(crate) write_batch: Option<PathBuf>,
    #[arg(skip)]
    pub(crate) only_write_batch: Option<PathBuf>,
    #[arg(skip)]
    pub(crate) read_batch: Option<PathBuf>,

    // Chunk 13: Resource limits and operational controls
    #[arg(skip)]
    pub(crate) bwlimit: Option<String>,
    #[arg(skip)]
    pub(crate) timeout_secs: Option<u64>,
    #[arg(skip)]
    pub(crate) stop_after_minutes: Option<u64>,
    #[arg(skip)]
    pub(crate) time_limit_minutes: Option<u64>,
    #[arg(skip)]
    pub(crate) stop_at: Option<String>,
    #[arg(skip)]
    pub(crate) max_alloc: Option<String>,
    #[arg(skip)]
    pub(crate) early_input: Option<String>,
    #[arg(skip)]
    pub(crate) outbuf: Option<String>,
    #[arg(skip)]
    pub(crate) protocol_version: Option<u32>,
    #[arg(skip)]
    pub(crate) iconv: Option<String>,
    #[arg(skip)]
    pub(crate) open_noatime: bool,

    #[arg(help = "Source and destination operands")]
    pub(crate) paths: Vec<String>,
}

impl Default for Cli {
    fn default() -> Self {
        Self {
            version: false,
            protocol_range: false,
            plan: false,
            recursive: false,
            no_recursive: false,
            inc_recursive: false,
            no_inc_recursive: false,
            preserve_times: false,
            no_times: false,
            archive: false,
            dry_run: false,
            delete: false,
            delete_mode: DeleteMode::None,
            whole_file: false,
            compress: false,
            compress_choice: None,
            compress_level: None,
            compress_threads: None,
            skip_compress: Vec::new(),
            quiet: 0,
            info_flags: Vec::new(),
            debug_flags: Vec::new(),
            msgs2stderr: false,
            no_msgs2stderr: false,
            stderr_mode: None,
            out_format: None,
            eight_bit_output: false,
            client_log_file: None,
            client_log_file_format: None,
            human_readable: 0,
            help: false,
            progress: false,
            relative: false,
            implied_dirs: true,
            transfer_dirs: false,
            mkpath: false,
            one_file_system: false,
            verbosity: 0,
            itemize_changes: false,
            stats: false,
            list_only: false,
            metadata_policy: CliMetadataPolicy::Portable,
            fail_on_metadata_loss: false,
            preserve_permissions: false,
            no_permissions: false,
            preserve_owner: false,
            preserve_group: false,
            executability: false,
            acls: false,
            xattrs: false,
            fake_super: false,
            atimes: false,
            crtimes: false,
            omit_dir_times: false,
            omit_link_times: false,
            vss: false,
            daemon_server: false,
            daemon_config: None,
            daemon_params: Vec::new(),
            daemon_no_detach: false,
            daemon_address: None,
            daemon_port: None,
            daemon_sockopts: None,
            daemon_connect_timeout_secs: None,
            daemon_no_motd: false,
            daemon_log_file: None,
            daemon_log_file_format: None,
            daemon_bwlimit: None,
            internal_server: false,
            internal_sender: false,
            includes: Vec::new(),
            excludes: Vec::new(),
            filters: Vec::new(),
            exclude_from: Vec::new(),
            include_from: Vec::new(),
            cvs_exclude: false,
            files_from: None,
            from0: false,
            checksum: false,
            checksum_choice: None,
            checksum_seed: None,
            size_only: false,
            ignore_times: false,
            partial: false,
            partial_dir: None,
            inplace: false,
            append_verify: false,
            append: false,
            update: false,
            existing: false,
            ignore_existing: false,
            max_size: None,
            min_size: None,
            modify_window: 0,
            ignore_missing_args: false,
            delete_missing_args: false,
            delete_excluded: false,
            ignore_errors: false,
            force: false,
            max_delete: None,
            backup: false,
            backup_dir: None,
            suffix: None,
            temp_dir: None,
            delay_updates: false,
            fsync: false,
            numeric_ids: false,
            user_maps: Vec::new(),
            group_maps: Vec::new(),
            chown: None,
            no_owner: false,
            no_group: false,
            chmod: None,
            remote_shell: None,
            password_file: None,
            copy_links: false,
            safe_links: false,
            copy_unsafe_links: false,
            copy_dirlinks: false,
            keep_dirlinks: false,
            munge_links: false,
            links: false,
            no_links: false,
            hard_links: false,
            devices: false,
            specials: false,
            no_devices: false,
            no_specials: false,
            copy_devices: false,
            write_devices: false,
            block_size: None,
            remote_options: Vec::new(),
            rsync_path: None,
            blocking_io: false,
            old_args: false,
            secluded_args: false,
            trust_sender: false,
            ipv4: false,
            ipv6: false,
            accepted_unsupported_options: Vec::new(),
            // Chunk 12
            compare_dest: Vec::new(),
            copy_dest: Vec::new(),
            link_dest: Vec::new(),
            sparse: false,
            preallocate: false,
            fuzzy: false,
            copy_as: None,
            super_flag: false,
            write_batch: None,
            only_write_batch: None,
            read_batch: None,
            // Chunk 13
            bwlimit: None,
            timeout_secs: None,
            stop_after_minutes: None,
            time_limit_minutes: None,
            stop_at: None,
            max_alloc: None,
            early_input: None,
            outbuf: None,
            protocol_version: None,
            iconv: None,
            open_noatime: false,
            paths: Vec::new(),
        }
    }
}
