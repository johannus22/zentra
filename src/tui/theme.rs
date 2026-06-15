use crate::state::Severity;
use anyhow::Result;
use ratatui::style::Color;
use serde::Deserialize;
use std::path::Path;

/// A complete set of semantic UI colors. Render code reads intent
/// (`theme.text_dim`), never a raw hue. All colors are explicit RGB (or
/// `Color::Reset` for transparent) so rendering is identical across terminals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Theme {
    pub id: String,
    pub name: String,
    pub bg: Color,
    pub surface: Color,
    pub border: Color,
    pub text: Color,
    pub text_dim: Color,
    pub text_muted: Color,
    pub accent: Color,
    pub accent_alt: Color,
    pub selection_bg: Color,
    pub selection_fg: Color,
    pub success: Color,
    pub warning: Color,
    pub error: Color,
    pub crit: Color,
    pub high: Color,
    pub medium: Color,
    pub low: Color,
    pub info: Color,
}

impl Theme {
    /// Map a finding severity to its themed color. Collapses the 5-arm match
    /// that was duplicated across scan_ui/results/pentest_ui.
    pub fn severity_color(&self, sev: &Severity) -> Color {
        match sev {
            Severity::Critical => self.crit,
            Severity::High => self.high,
            Severity::Medium => self.medium,
            Severity::Low => self.low,
            Severity::Info => self.info,
        }
    }
}

impl Default for Theme {
    fn default() -> Self {
        muted_slate()
    }
}

/// Parse `#rrggbb` (case-insensitive) into `Color::Rgb`, or the keywords
/// `reset`/`transparent` into `Color::Reset`. Returns `None` on anything else.
pub fn parse_color(s: &str) -> Option<Color> {
    let s = s.trim();
    if s.eq_ignore_ascii_case("reset") || s.eq_ignore_ascii_case("transparent") {
        return Some(Color::Reset);
    }
    let hex = s.strip_prefix('#')?;
    if hex.len() != 6 {
        return None;
    }
    let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
    let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
    let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
    Some(Color::Rgb(r, g, b))
}

pub fn muted_slate() -> Theme {
    Theme {
        id: "muted_slate".into(),
        name: "Muted Slate".into(),
        bg: Color::Rgb(0x1b, 0x20, 0x27),
        surface: Color::Rgb(0x23, 0x2a, 0x33),
        border: Color::Rgb(0x3a, 0x43, 0x4f),
        text: Color::Rgb(0xc8, 0xcd, 0xd4),
        text_dim: Color::Rgb(0x8a, 0x94, 0xa3),
        text_muted: Color::Rgb(0x5c, 0x66, 0x75),
        accent: Color::Rgb(0x6f, 0xb3, 0xc9),
        accent_alt: Color::Rgb(0xb4, 0x8e, 0xad),
        selection_bg: Color::Rgb(0x2c, 0x3a, 0x44),
        selection_fg: Color::Rgb(0xdf, 0xe6, 0xee),
        success: Color::Rgb(0x8f, 0xbf, 0x7f),
        warning: Color::Rgb(0xd8, 0xc0, 0x6a),
        error: Color::Rgb(0xe0, 0x6c, 0x75),
        crit: Color::Rgb(0xe0, 0x6c, 0x75),
        high: Color::Rgb(0xe5, 0xa2, 0x6b),
        medium: Color::Rgb(0xd8, 0xc0, 0x6a),
        low: Color::Rgb(0x6c, 0x93, 0xc9),
        info: Color::Rgb(0x6b, 0x75, 0x85),
    }
}

pub fn dawn() -> Theme {
    Theme {
        id: "dawn".into(),
        name: "Dawn".into(),
        bg: Color::Rgb(0xf4, 0xf1, 0xea),
        surface: Color::Rgb(0xe9, 0xe4, 0xd9),
        border: Color::Rgb(0xcf, 0xc7, 0xb6),
        text: Color::Rgb(0x34, 0x30, 0x2a),
        text_dim: Color::Rgb(0x6e, 0x66, 0x58),
        text_muted: Color::Rgb(0x9a, 0x91, 0x7f),
        accent: Color::Rgb(0x3d, 0x7e, 0xa6),
        accent_alt: Color::Rgb(0x8a, 0x5a, 0x8c),
        selection_bg: Color::Rgb(0xdd, 0xd5, 0xc6),
        selection_fg: Color::Rgb(0x1f, 0x1c, 0x17),
        success: Color::Rgb(0x4f, 0x8a, 0x4f),
        warning: Color::Rgb(0xb0, 0x7d, 0x2b),
        error: Color::Rgb(0xb5, 0x49, 0x5b),
        crit: Color::Rgb(0xb5, 0x49, 0x5b),
        high: Color::Rgb(0xc2, 0x70, 0x1f),
        medium: Color::Rgb(0x9a, 0x7d, 0x1e),
        low: Color::Rgb(0x3d, 0x7e, 0xa6),
        info: Color::Rgb(0x8a, 0x81, 0x70),
    }
}

pub fn matrix() -> Theme {
    Theme {
        id: "matrix".into(),
        name: "Matrix".into(),
        bg: Color::Rgb(0x0a, 0x0f, 0x0a),
        surface: Color::Rgb(0x0f, 0x18, 0x0f),
        border: Color::Rgb(0x1f, 0x3a, 0x1f),
        text: Color::Rgb(0xb8, 0xf5, 0xb0),
        text_dim: Color::Rgb(0x5f, 0xae, 0x5a),
        text_muted: Color::Rgb(0x2f, 0x6f, 0x2c),
        accent: Color::Rgb(0x39, 0xff, 0x14),
        accent_alt: Color::Rgb(0x7c, 0xff, 0x5c),
        selection_bg: Color::Rgb(0x14, 0x33, 0x14),
        selection_fg: Color::Rgb(0xd6, 0xff, 0xce),
        success: Color::Rgb(0x39, 0xff, 0x14),
        warning: Color::Rgb(0xd8, 0xd8, 0x6a),
        error: Color::Rgb(0xff, 0x5f, 0x56),
        crit: Color::Rgb(0xff, 0x5f, 0x56),
        high: Color::Rgb(0xff, 0x9f, 0x43),
        medium: Color::Rgb(0xd8, 0xd8, 0x6a),
        low: Color::Rgb(0x5f, 0xae, 0x5a),
        info: Color::Rgb(0x2f, 0x6f, 0x2c),
    }
}

pub fn nord() -> Theme {
    Theme {
        id: "nord".into(),
        name: "Nord".into(),
        bg: Color::Rgb(0x2e, 0x34, 0x40),
        surface: Color::Rgb(0x3b, 0x42, 0x52),
        border: Color::Rgb(0x4c, 0x56, 0x6a),
        text: Color::Rgb(0xd8, 0xde, 0xe9),
        text_dim: Color::Rgb(0x7b, 0x88, 0xa1),
        text_muted: Color::Rgb(0x4c, 0x56, 0x6a),
        accent: Color::Rgb(0x88, 0xc0, 0xd0),
        accent_alt: Color::Rgb(0xb4, 0x8e, 0xad),
        selection_bg: Color::Rgb(0x43, 0x4c, 0x5e),
        selection_fg: Color::Rgb(0xec, 0xef, 0xf4),
        success: Color::Rgb(0xa3, 0xbe, 0x8c),
        warning: Color::Rgb(0xeb, 0xcb, 0x8b),
        error: Color::Rgb(0xbf, 0x61, 0x6a),
        crit: Color::Rgb(0xbf, 0x61, 0x6a),
        high: Color::Rgb(0xd0, 0x87, 0x70),
        medium: Color::Rgb(0xeb, 0xcb, 0x8b),
        low: Color::Rgb(0x81, 0xa1, 0xc1),
        info: Color::Rgb(0x6b, 0x74, 0x88),
    }
}

pub fn tokyo_night() -> Theme {
    Theme {
        id: "tokyo_night".into(),
        name: "Tokyo Night".into(),
        bg: Color::Rgb(0x1a, 0x1b, 0x26),
        surface: Color::Rgb(0x24, 0x28, 0x3b),
        border: Color::Rgb(0x3b, 0x42, 0x61),
        text: Color::Rgb(0xc0, 0xca, 0xf5),
        text_dim: Color::Rgb(0xa9, 0xb1, 0xd6),
        text_muted: Color::Rgb(0x56, 0x5f, 0x89),
        accent: Color::Rgb(0x7a, 0xa2, 0xf7),
        accent_alt: Color::Rgb(0xbb, 0x9a, 0xf7),
        selection_bg: Color::Rgb(0x2e, 0x3c, 0x64),
        selection_fg: Color::Rgb(0xc0, 0xca, 0xf5),
        success: Color::Rgb(0x9e, 0xce, 0x6a),
        warning: Color::Rgb(0xe0, 0xaf, 0x68),
        error: Color::Rgb(0xf7, 0x76, 0x8e),
        crit: Color::Rgb(0xf7, 0x76, 0x8e),
        high: Color::Rgb(0xff, 0x9e, 0x64),
        medium: Color::Rgb(0xe0, 0xaf, 0x68),
        low: Color::Rgb(0x7d, 0xcf, 0xff),
        info: Color::Rgb(0x56, 0x5f, 0x89),
    }
}

pub fn dracula() -> Theme {
    Theme {
        id: "dracula".into(),
        name: "Dracula".into(),
        bg: Color::Rgb(0x28, 0x2a, 0x36),
        surface: Color::Rgb(0x34, 0x37, 0x46),
        border: Color::Rgb(0x44, 0x47, 0x5a),
        text: Color::Rgb(0xf8, 0xf8, 0xf2),
        text_dim: Color::Rgb(0xa8, 0xa8, 0xc0),
        text_muted: Color::Rgb(0x62, 0x72, 0xa4),
        accent: Color::Rgb(0xbd, 0x93, 0xf9),
        accent_alt: Color::Rgb(0xff, 0x79, 0xc6),
        selection_bg: Color::Rgb(0x44, 0x47, 0x5a),
        selection_fg: Color::Rgb(0xf8, 0xf8, 0xf2),
        success: Color::Rgb(0x50, 0xfa, 0x7b),
        warning: Color::Rgb(0xf1, 0xfa, 0x8c),
        error: Color::Rgb(0xff, 0x55, 0x55),
        crit: Color::Rgb(0xff, 0x55, 0x55),
        high: Color::Rgb(0xff, 0xb8, 0x6c),
        medium: Color::Rgb(0xf1, 0xfa, 0x8c),
        low: Color::Rgb(0x8b, 0xe9, 0xfd),
        info: Color::Rgb(0x62, 0x72, 0xa4),
    }
}

pub fn gruvbox_dark() -> Theme {
    Theme {
        id: "gruvbox_dark".into(),
        name: "Gruvbox Dark".into(),
        bg: Color::Rgb(0x28, 0x28, 0x28),
        surface: Color::Rgb(0x3c, 0x38, 0x36),
        border: Color::Rgb(0x50, 0x49, 0x45),
        text: Color::Rgb(0xeb, 0xdb, 0xb2),
        text_dim: Color::Rgb(0xa8, 0x99, 0x84),
        text_muted: Color::Rgb(0x66, 0x5c, 0x54),
        accent: Color::Rgb(0x83, 0xa5, 0x98),
        accent_alt: Color::Rgb(0xd3, 0x86, 0x9b),
        selection_bg: Color::Rgb(0x3c, 0x38, 0x36),
        selection_fg: Color::Rgb(0xfb, 0xf1, 0xc7),
        success: Color::Rgb(0xb8, 0xbb, 0x26),
        warning: Color::Rgb(0xfa, 0xbd, 0x2f),
        error: Color::Rgb(0xfb, 0x49, 0x34),
        crit: Color::Rgb(0xfb, 0x49, 0x34),
        high: Color::Rgb(0xfe, 0x80, 0x19),
        medium: Color::Rgb(0xfa, 0xbd, 0x2f),
        low: Color::Rgb(0x83, 0xa5, 0x98),
        info: Color::Rgb(0x92, 0x83, 0x74),
    }
}

pub fn monokai() -> Theme {
    Theme {
        id: "monokai".into(),
        name: "Monokai".into(),
        bg: Color::Rgb(0x27, 0x28, 0x22),
        surface: Color::Rgb(0x3e, 0x3d, 0x32),
        border: Color::Rgb(0x49, 0x48, 0x3e),
        text: Color::Rgb(0xf8, 0xf8, 0xf2),
        text_dim: Color::Rgb(0xa5, 0x9f, 0x85),
        text_muted: Color::Rgb(0x75, 0x71, 0x5e),
        accent: Color::Rgb(0x66, 0xd9, 0xef),
        accent_alt: Color::Rgb(0xae, 0x81, 0xff),
        selection_bg: Color::Rgb(0x49, 0x48, 0x3e),
        selection_fg: Color::Rgb(0xf8, 0xf8, 0xf2),
        success: Color::Rgb(0xa6, 0xe2, 0x2e),
        warning: Color::Rgb(0xe6, 0xdb, 0x74),
        error: Color::Rgb(0xf9, 0x26, 0x72),
        crit: Color::Rgb(0xf9, 0x26, 0x72),
        high: Color::Rgb(0xfd, 0x97, 0x1f),
        medium: Color::Rgb(0xe6, 0xdb, 0x74),
        low: Color::Rgb(0x66, 0xd9, 0xef),
        info: Color::Rgb(0x75, 0x71, 0x5e),
    }
}

pub fn builtin_themes() -> Vec<Theme> {
    vec![
        muted_slate(),
        dawn(),
        matrix(),
        nord(),
        tokyo_night(),
        dracula(),
        gruvbox_dark(),
        monokai(),
    ]
}

/// `~/.zentra/themes`
fn custom_themes_dir() -> Result<std::path::PathBuf> {
    Ok(crate::config::global_zentra_dir()?.join("themes"))
}

#[derive(Deserialize, Default)]
struct ThemeFile {
    name: Option<String>,
    bg: Option<String>,
    surface: Option<String>,
    border: Option<String>,
    text: Option<String>,
    text_dim: Option<String>,
    text_muted: Option<String>,
    accent: Option<String>,
    accent_alt: Option<String>,
    selection_bg: Option<String>,
    selection_fg: Option<String>,
    success: Option<String>,
    warning: Option<String>,
    error: Option<String>,
    crit: Option<String>,
    high: Option<String>,
    medium: Option<String>,
    low: Option<String>,
    info: Option<String>,
}

/// Load one custom theme. Starts from Muted Slate and overrides only the keys
/// present and parseable in the file (partial themes are valid).
fn load_custom(path: &Path) -> Result<Theme> {
    let content = std::fs::read_to_string(path)?;
    let f: ThemeFile = toml::from_str(&content)?;
    let mut t = muted_slate();
    t.id = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("custom")
        .to_string();
    if let Some(n) = f.name {
        t.name = n;
    }
    macro_rules! set {
        ($field:ident) => {
            if let Some(c) = f.$field.as_deref().and_then(parse_color) {
                t.$field = c;
            }
        };
    }
    set!(bg);
    set!(surface);
    set!(border);
    set!(text);
    set!(text_dim);
    set!(text_muted);
    set!(accent);
    set!(accent_alt);
    set!(selection_bg);
    set!(selection_fg);
    set!(success);
    set!(warning);
    set!(error);
    set!(crit);
    set!(high);
    set!(medium);
    set!(low);
    set!(info);
    Ok(t)
}

/// Built-ins followed by valid custom themes from `~/.zentra/themes/*.toml`.
/// Malformed files are skipped silently (this runs before the TUI takes the
/// screen, so we avoid writing to stderr).
pub fn load_all() -> Vec<Theme> {
    let mut themes = builtin_themes();
    if let Ok(dir) = custom_themes_dir() {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("toml") {
                    if let Ok(t) = load_custom(&path) {
                        themes.push(t);
                    }
                }
            }
        }
    }
    themes
}

/// Resolve a theme by id, falling back to Muted Slate.
pub fn resolve(name: Option<&str>) -> Theme {
    let target = name.unwrap_or("muted_slate");
    load_all()
        .into_iter()
        .find(|t| t.id == target)
        .unwrap_or_else(muted_slate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex() {
        assert_eq!(parse_color("#1b2027"), Some(Color::Rgb(0x1b, 0x20, 0x27)));
        assert_eq!(parse_color("#FFFFFF"), Some(Color::Rgb(255, 255, 255)));
    }

    #[test]
    fn parses_reset_keyword() {
        assert_eq!(parse_color("reset"), Some(Color::Reset));
        assert_eq!(parse_color("transparent"), Some(Color::Reset));
    }

    #[test]
    fn rejects_invalid() {
        assert_eq!(parse_color("blue"), None);
        assert_eq!(parse_color("#12"), None);
        assert_eq!(parse_color("#gggggg"), None);
    }

    #[test]
    fn builtins_present() {
        let ids: Vec<_> = builtin_themes().into_iter().map(|t| t.id).collect();
        assert_eq!(
            ids,
            [
                "muted_slate",
                "dawn",
                "matrix",
                "nord",
                "tokyo_night",
                "dracula",
                "gruvbox_dark",
                "monokai"
            ]
        );
    }

    #[test]
    fn resolve_unknown_falls_back_to_default() {
        assert_eq!(resolve(Some("nope")).id, "muted_slate");
        assert_eq!(resolve(None).id, "muted_slate");
    }

    #[test]
    fn severity_color_maps_each_variant() {
        let t = muted_slate();
        assert_eq!(t.severity_color(&Severity::Critical), t.crit);
        assert_eq!(t.severity_color(&Severity::Info), t.info);
    }

    #[test]
    fn load_custom_partial_inherits_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ocean.toml");
        std::fs::write(&path, "name = \"Ocean\"\naccent = \"#7aa2f7\"\n").unwrap();
        let t = load_custom(&path).unwrap();
        assert_eq!(t.id, "ocean");
        assert_eq!(t.name, "Ocean");
        assert_eq!(t.accent, Color::Rgb(0x7a, 0xa2, 0xf7));
        // unset key inherits Muted Slate
        assert_eq!(t.bg, muted_slate().bg);
    }
}
