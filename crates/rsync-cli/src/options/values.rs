use super::*;

pub(super) fn parse_metadata_policy(value: &str) -> Result<CliMetadataPolicy> {
    match value {
        "portable" => Ok(CliMetadataPolicy::Portable),
        "posix" => Ok(CliMetadataPolicy::Posix),
        "ntfs-native" => Ok(CliMetadataPolicy::NtfsNative),
        _ => bail!("invalid --metadata-policy value `{value}`"),
    }
}

pub(super) fn parse_i64(value: &str, option: &str) -> Result<i64> {
    value
        .parse()
        .map_err(|_| anyhow::anyhow!("option --{option} expects an integer"))
}

pub(super) fn parse_i32(value: &str, option: &str) -> Result<i32> {
    value
        .parse()
        .map_err(|_| anyhow::anyhow!("option --{option} expects a 32-bit integer"))
}

pub(super) fn parse_u32(value: &str, option: &str) -> Result<u32> {
    value
        .parse()
        .map_err(|_| anyhow::anyhow!("option --{option} expects a non-negative integer"))
}

pub(super) fn parse_u16(value: &str, option: &str) -> Result<u16> {
    value
        .parse()
        .map_err(|_| anyhow::anyhow!("option --{option} expects a 16-bit integer"))
}

pub(super) fn parse_u64(value: &str, option: &str) -> Result<u64> {
    value
        .parse()
        .map_err(|_| anyhow::anyhow!("option --{option} expects a non-negative integer"))
}

pub(super) fn parse_usize(value: &str, option: &str) -> Result<usize> {
    value
        .parse()
        .map_err(|_| anyhow::anyhow!("option --{option} expects a non-negative integer"))
}

pub(super) fn parse_max_delete(value: &str) -> Result<usize> {
    if value == "-1" {
        return Ok(0);
    }
    value
        .parse()
        .map_err(|_| anyhow::anyhow!("option --max-delete expects a non-negative integer or -1"))
}

pub(super) fn parse_size(value: &str) -> Result<u64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("size value cannot be empty");
    }
    let split = trimmed
        .find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(trimmed.len());
    let (digits, suffix) = trimmed.split_at(split);
    let number: u64 = digits
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid size value `{value}`"))?;
    let multiplier = match suffix.to_ascii_lowercase().as_str() {
        "" => 1,
        "k" | "kb" => 1024,
        "m" | "mb" => 1024 * 1024,
        "g" | "gb" => 1024 * 1024 * 1024,
        _ => bail!("invalid size suffix in `{value}`"),
    };
    Ok(number.saturating_mul(multiplier))
}

pub(super) fn parse_bwlimit_value(value: &str) -> Result<Option<u64>> {
    let bytes = parse_scaled_number(value, 1024.0, "--bwlimit")?;
    if bytes == 0 {
        return Ok(None);
    }
    Ok(Some(bytes))
}

pub(super) fn parse_max_alloc_value(value: &str) -> Result<Option<u64>> {
    let bytes = parse_scaled_number(value, 1.0, "--max-alloc")?;
    if bytes == 0 {
        return Ok(None);
    }
    Ok(Some(bytes))
}

pub(super) fn parse_scaled_number(
    value: &str,
    default_multiplier: f64,
    option: &str,
) -> Result<u64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("{option} value cannot be empty");
    }
    let split = trimmed
        .find(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .unwrap_or(trimmed.len());
    let (digits, suffix) = trimmed.split_at(split);
    if digits.is_empty() || digits == "." {
        bail!("{option} value `{value}` is not a valid size");
    }
    let number = digits
        .parse::<f64>()
        .map_err(|_| anyhow::anyhow!("{option} value `{value}` is not a valid size"))?;
    if !number.is_finite() || number < 0.0 {
        bail!("{option} value `{value}` must be non-negative");
    }
    let multiplier = match suffix.to_ascii_lowercase().as_str() {
        "" => default_multiplier,
        "b" => 1.0,
        "k" | "kb" | "kib" => 1024.0,
        "m" | "mb" | "mib" => 1024.0 * 1024.0,
        "g" | "gb" | "gib" => 1024.0 * 1024.0 * 1024.0,
        "t" | "tb" | "tib" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        "p" | "pb" | "pib" => 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => bail!("{option} value `{value}` has an unsupported size suffix"),
    };
    let bytes = (number * multiplier).round();
    if bytes > u64::MAX as f64 {
        bail!("{option} value `{value}` exceeds the supported range");
    }
    Ok(bytes as u64)
}

pub(super) fn parse_outbuf_value(value: &str) -> Result<String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "n" | "none" | "unbuffered" => Ok("N".to_string()),
        "l" | "line" => Ok("L".to_string()),
        "b" | "block" | "full" => Ok("B".to_string()),
        _ => bail!("--outbuf expects N, L, or B"),
    }
}

pub(super) fn validate_stop_at_value(value: &str) -> Result<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("--stop-at value cannot be empty");
    }
    let time = trimmed.rsplit_once('T').map_or(trimmed, |(_, time)| time);
    if time.contains(':') {
        validate_stop_at_time(time)?;
    }
    Ok(())
}

pub(super) fn validate_stop_at_time(value: &str) -> Result<()> {
    let parts: Vec<_> = value.split(':').collect();
    if parts.len() < 2 || parts.len() > 3 {
        bail!("--stop-at time must use HH:MM or HH:MM:SS");
    }
    let hour = parts[0]
        .parse::<u8>()
        .map_err(|_| anyhow::anyhow!("--stop-at hour is not valid"))?;
    let minute = parts[1]
        .parse::<u8>()
        .map_err(|_| anyhow::anyhow!("--stop-at minute is not valid"))?;
    let second = if parts.len() == 3 {
        parts[2]
            .parse::<u8>()
            .map_err(|_| anyhow::anyhow!("--stop-at second is not valid"))?
    } else {
        0
    };
    if hour > 23 || minute > 59 || second > 59 {
        bail!("--stop-at time is outside the valid clock range");
    }
    Ok(())
}
