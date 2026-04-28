#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VssSnapshotStatus {
    pub requested: bool,
    pub available: bool,
    pub message: String,
}

pub fn vss_snapshot_status(requested: bool) -> VssSnapshotStatus {
    if requested {
        VssSnapshotStatus {
            requested: true,
            available: false,
            message: "VSS snapshot source mode is not implemented in this build".to_string(),
        }
    } else {
        VssSnapshotStatus {
            requested: false,
            available: false,
            message: "VSS snapshot source mode was not requested".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requested_vss_status_is_explicitly_unavailable() {
        let status = vss_snapshot_status(true);

        assert!(status.requested);
        assert!(!status.available);
        assert!(status.message.contains("not implemented"));
    }
}
