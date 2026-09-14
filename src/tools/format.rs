/// Formats a byte count as a human-readable string (e.g. "1.5 KB").
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit_index = 0;
    while value >= 1024.0 && unit_index < UNITS.len() - 1 {
        value /= 1024.0;
        unit_index += 1;
    }
    if unit_index == 0 {
        format!("{value:.0} {}", UNITS[unit_index])
    } else {
        format!("{value:.1} {}", UNITS[unit_index])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_bytes_without_decimal() {
        assert_eq!(human_bytes(512), "512 B");
    }

    #[test]
    fn formats_kilobytes_with_one_decimal() {
        assert_eq!(human_bytes(1536), "1.5 KB");
    }
}
