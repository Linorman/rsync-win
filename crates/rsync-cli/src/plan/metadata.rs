use super::*;

pub(crate) fn parse_chmod_rules(cli: &Cli, report: &mut Report) -> Option<ChmodRules> {
    let Some(chmod) = &cli.chmod else {
        return None;
    };
    match chmod.parse::<ChmodRules>() {
        Ok(rules) => Some(rules),
        Err(err) => {
            report.error("E_CHMOD", err.to_string());
            None
        }
    }
}

pub(crate) fn add_metadata_degradations(
    report: &mut Report,
    degradations: Vec<MetadataDegradation>,
    fail_on_loss: bool,
) {
    for degradation in degradations {
        let severity = if fail_on_loss && degradation.is_loss() {
            Severity::Error
        } else {
            Severity::Warning
        };
        let code = metadata_code(degradation.feature, severity);
        let message = format!(
            "{} metadata {}: {}",
            degradation.feature.label(),
            degradation.action.label(),
            degradation.message
        );
        report.push(Diagnostic::new(severity, code, message));
    }
}

pub(crate) fn archive_mode_degradations_for_cli(
    cli: &Cli,
    metadata_policy: MetadataPolicy,
) -> Vec<MetadataDegradation> {
    archive_mode_degradations(metadata_policy)
        .into_iter()
        .filter(|degradation| {
            !(cli.no_permissions && degradation.feature == MetadataFeature::Permissions
                || cli.no_owner && degradation.feature == MetadataFeature::Owner
                || cli.no_group && degradation.feature == MetadataFeature::Group
                || cli.no_devices && degradation.feature == MetadataFeature::Device
                || cli.no_specials && degradation.feature == MetadataFeature::SpecialFile)
        })
        .collect()
}

pub(crate) fn posix_metadata_request_from_cli(cli: &Cli) -> PosixMetadataRequest {
    PosixMetadataRequest {
        permissions: cli_preserve_permissions(cli),
        owner: cli_preserve_owner(cli),
        group: cli_preserve_group(cli),
        numeric_ids: cli.numeric_ids,
        chmod: cli.chmod.is_some(),
        executability: cli.executability,
        symlink_mtime: cli.archive && !cli.omit_link_times,
        acls: cli.acls,
        xattrs: cli.xattrs,
        fake_super: cli.fake_super,
        atimes: cli.atimes,
        crtimes: cli.crtimes,
        omit_dir_times: cli.omit_dir_times,
        user_map: !cli.user_maps.is_empty(),
        group_map: !cli.group_maps.is_empty(),
        chown: cli.chown.is_some(),
    }
}

pub(crate) fn posix_metadata_degradations_for_plan(
    cli: &Cli,
    metadata_policy: MetadataPolicy,
    remote_direction: Option<TransferDirection>,
    daemon_direction: Option<TransferDirection>,
) -> Vec<MetadataDegradation> {
    let mut request = posix_metadata_request_from_cli(cli);

    if daemon_direction.is_none() && remote_direction == Some(TransferDirection::Push) {
        request.chmod = false;
        request.executability = false;
        request.owner = false;
        request.group = false;
        request.acls = false;
        request.xattrs = false;
        request.fake_super = false;
        request.atimes = false;
        request.crtimes = false;
        request.omit_dir_times = false;
        request.user_map = false;
        request.group_map = false;
        request.chown = false;
    }

    request.degradations(metadata_policy)
}

pub(crate) fn posix_metadata_summary(plan: &TransferPlan) -> String {
    let mut parts = Vec::new();
    if plan.preserve_permissions {
        parts.push("perms");
    }
    if plan.preserve_owner {
        parts.push("owner");
    }
    if plan.preserve_group {
        parts.push("group");
    }
    if plan.preserve_executability {
        parts.push("executability");
    }
    if plan.preserve_acls {
        parts.push("acls");
    }
    if plan.preserve_xattrs {
        parts.push("xattrs");
    }
    if plan.hard_links {
        parts.push("hard-links");
    }
    if plan.fake_super {
        parts.push("fake-super");
    }
    if plan.omit_dir_times {
        parts.push("omit-dir-times");
    }
    if plan.atimes {
        parts.push("atimes");
    }
    if plan.crtimes {
        parts.push("crtimes");
    }
    if plan.omit_link_times {
        parts.push("omit-link-times");
    }
    if plan.numeric_ids {
        parts.push("numeric-ids");
    }
    if plan.chmod.is_some() {
        parts.push("chmod");
    }
    if !plan.user_maps.is_empty() {
        parts.push("usermap");
    }
    if !plan.group_maps.is_empty() {
        parts.push("groupmap");
    }
    if plan.chown.is_some() {
        parts.push("chown");
    }

    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(",")
    }
}
