pub(crate) fn parse_bwlimit_quiet(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let (number, unit) = match trimmed.as_bytes().last().copied() {
        Some(b'B') | Some(b'b') => (&trimmed[..trimmed.len() - 1], 1_f64),
        Some(b'K') | Some(b'k') => (&trimmed[..trimmed.len() - 1], 1024_f64),
        Some(b'M') | Some(b'm') => (&trimmed[..trimmed.len() - 1], 1024_f64 * 1024_f64),
        Some(b'G') | Some(b'g') => (
            &trimmed[..trimmed.len() - 1],
            1024_f64 * 1024_f64 * 1024_f64,
        ),
        _ => (trimmed, 1024_f64),
    };
    let rate = number.trim().parse::<f64>().ok()?;
    if !rate.is_finite() || rate <= 0.0 {
        return None;
    }
    let bytes_per_second = (rate * unit).round();
    if bytes_per_second < 1.0 || bytes_per_second > u64::MAX as f64 {
        return None;
    }
    Some(bytes_per_second as u64)
}

pub(crate) fn format_bwlimit(value: &str) -> String {
    let trimmed = value.trim();
    let (number, unit_label) = match trimmed.as_bytes().last().copied() {
        Some(b'B') | Some(b'b') => (number_str(trimmed, 1), "B/s"),
        Some(b'K') | Some(b'k') => (number_str(trimmed, 1), "KB/s"),
        Some(b'M') | Some(b'm') => (number_str(trimmed, 1), "MB/s"),
        Some(b'G') | Some(b'g') => (number_str(trimmed, 1), "GB/s"),
        _ => (trimmed, "KB/s"),
    };
    let num: f64 = match number.parse::<f64>() {
        Ok(n) if n.is_finite() => n,
        _ => return trimmed.to_string(),
    };
    format!("{:.1} {}", num, unit_label)
}

pub(crate) fn number_str(s: &str, trim: usize) -> &str {
    let end = s.len().saturating_sub(trim);
    &s[..end]
}

pub(crate) fn parse_max_alloc_quiet(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let (number_str, multiplier) = match trimmed.as_bytes().last().copied() {
        Some(b'K') | Some(b'k') => (&trimmed[..trimmed.len() - 1], 1024_u64),
        Some(b'M') | Some(b'm') => (&trimmed[..trimmed.len() - 1], 1024 * 1024),
        Some(b'G') | Some(b'g') => (&trimmed[..trimmed.len() - 1], 1024 * 1024 * 1024),
        _ => (trimmed, 1),
    };
    let number = number_str.trim().parse::<f64>().ok()?;
    if !number.is_finite() || number <= 0.0 {
        return None;
    }
    let bytes = (number * multiplier as f64).round();
    if bytes < 1.0 || bytes > u64::MAX as f64 {
        return None;
    }
    Some(bytes as u64)
}

pub(crate) fn format_max_alloc(value: &str) -> String {
    let trimmed = value.trim();
    match trimmed.as_bytes().last().copied() {
        Some(b'G') | Some(b'g') => {
            let n: &str = &trimmed[..trimmed.len() - 1];
            format!("{} GB", n.trim())
        }
        Some(b'M') | Some(b'm') => {
            let n: &str = &trimmed[..trimmed.len() - 1];
            format!("{} MB", n.trim())
        }
        Some(b'K') | Some(b'k') => {
            let n: &str = &trimmed[..trimmed.len() - 1];
            format!("{} KB", n.trim())
        }
        _ => format!("{trimmed} B"),
    }
}
