// SPDX-FileCopyrightText: 2026 B.O.P.E Scanner contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of B.O.P.E Scanner, a modified version of aeterna-rongroi. Using it to evade detection is out of scope — see AGENTS.md.

//! A minimal PDF 1.4 writer for the saved report (B.O.P.E, ADR 0129).
//!
//! No dependency, no network, no fonts embedded: the pages use two of the fourteen standard PDF fonts
//! (Courier for the body, so the text report's columns stay aligned, and Helvetica-Bold for headings)
//! with `WinAnsiEncoding`, which covers Portuguese. A character that encoding cannot hold is written as
//! `?` — Thai text, for one, so a report in Thai is better saved as HTML. The output is deterministic:
//! the same lines give the same bytes, so its SHA-256 can be published beside it like the other
//! formats'.

use std::fmt::Write as _;

/// Page width and height in points (A4).
const PAGE_W: f32 = 595.0;
const PAGE_H: f32 = 842.0;
const MARGIN: f32 = 40.0;
const BODY_SIZE: f32 = 8.0;
const LEADING: f32 = 10.0;
/// Characters per line at [`BODY_SIZE`] in Courier (0.6 em per character).
pub const COLUMNS: usize = 106;

/// One line of the document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// A heading, in bold.
    Heading(String),
    /// Body text; wrapped at [`COLUMNS`].
    Text(String),
}

/// Maps a character to its `WinAnsiEncoding` (Windows-1252) byte, or `None`.
pub fn win_ansi(c: char) -> Option<u8> {
    let code = u32::from(c);
    if code < 0x80 || (0xA0..=0xFF).contains(&code) {
        return u8::try_from(code).ok();
    }
    Some(match c {
        '€' => 0x80,
        '‚' => 0x82,
        'ƒ' => 0x83,
        '„' => 0x84,
        '…' => 0x85,
        '†' => 0x86,
        '‡' => 0x87,
        'ˆ' => 0x88,
        '‰' => 0x89,
        'Š' => 0x8A,
        '‹' => 0x8B,
        'Œ' => 0x8C,
        'Ž' => 0x8E,
        '‘' => 0x91,
        '’' => 0x92,
        '“' => 0x93,
        '”' => 0x94,
        '•' => 0x95,
        '–' => 0x96,
        '—' => 0x97,
        '˜' => 0x98,
        '™' => 0x99,
        'š' => 0x9A,
        '›' => 0x9B,
        'œ' => 0x9C,
        'ž' => 0x9E,
        'Ÿ' => 0x9F,
        _ => return None,
    })
}

/// Text as a PDF literal string in `WinAnsiEncoding`: `\`, `(` and `)` escaped, bytes past ASCII as
/// octal, and a few common symbols spelt in ASCII.
pub fn literal(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('(');
    for c in text.chars() {
        let replacement = match c {
            '→' => Some("->"),
            '←' => Some("<-"),
            '≥' => Some(">="),
            '≤' => Some("<="),
            '✓' => Some("v"),
            '\t' => Some("    "),
            _ => None,
        };
        if let Some(r) = replacement {
            out.push_str(r);
            continue;
        }
        match win_ansi(c) {
            Some(b'\\') => out.push_str("\\\\"),
            Some(b'(') => out.push_str("\\("),
            Some(b')') => out.push_str("\\)"),
            Some(b) if (0x20..0x7F).contains(&b) => out.push(char::from(b)),
            Some(b) => {
                let _ = write!(out, "\\{b:03o}");
            }
            None => out.push('?'),
        }
    }
    out.push(')');
    out
}

/// Splits `text` into lines of at most `width` characters, at spaces where it can, keeping the
/// indentation of the first line on the lines it wraps to.
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= width {
        return vec![text.to_owned()];
    }
    let indent: String = chars.iter().take_while(|c| **c == ' ').collect();
    let indent = if indent.chars().count() > width / 2 {
        String::new()
    } else {
        format!("{indent}  ")
    };
    let mut lines = Vec::new();
    let mut rest: &[char] = &chars;
    let mut first = true;
    while !rest.is_empty() {
        let room = if first {
            width
        } else {
            width - indent.chars().count()
        };
        if rest.len() <= room {
            let s: String = rest.iter().collect();
            lines.push(if first { s } else { format!("{indent}{s}") });
            break;
        }
        let cut = rest[..room]
            .iter()
            .rposition(|c| *c == ' ')
            .filter(|p| *p > room / 3)
            .unwrap_or(room);
        let s: String = rest[..cut].iter().collect();
        lines.push(if first { s } else { format!("{indent}{s}") });
        rest = &rest[cut..];
        while rest.first() == Some(&' ') {
            rest = &rest[1..];
        }
        first = false;
    }
    lines
}

/// Document information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    /// Title.
    pub title: String,
    /// Producer, with the program's version.
    pub producer: String,
    /// Creation time as RFC 3339 UTC; written as a PDF date.
    pub created: String,
    /// The footer printed on every page before the page number.
    pub footer: String,
}

fn pdf_date(rfc3339: &str) -> String {
    let digits: String = rfc3339
        .chars()
        .filter(char::is_ascii_digit)
        .take(14)
        .collect();
    format!("D:{digits}Z")
}

/// Renders `lines` to a PDF document.
pub fn render(info: &Info, lines: &[Line]) -> Vec<u8> {
    // Lay out pages: (842 - 2 × 40 - 20) / 10 lines fit on one.
    let per_page = 74;
    let mut laid: Vec<(bool, String)> = Vec::new();
    for line in lines {
        match line {
            Line::Heading(t) => {
                for w in wrap(t, COLUMNS - 10) {
                    laid.push((true, w));
                }
            }
            Line::Text(t) => {
                for w in wrap(t, COLUMNS) {
                    laid.push((false, w));
                }
            }
        }
    }
    let pages: Vec<&[(bool, String)]> = if laid.is_empty() {
        vec![&[]]
    } else {
        laid.chunks(per_page).collect()
    };
    let total = pages.len();

    let mut objects: Vec<String> = Vec::new();
    // 1 catalog, 2 pages, 3 font body, 4 font bold, 5 info; then per page: page, contents.
    let first_page = 6;
    let kids: Vec<String> = (0..total)
        .map(|i| format!("{} 0 R", first_page + i * 2))
        .collect();
    objects.push("<< /Type /Catalog /Pages 2 0 R >>".to_owned());
    objects.push(format!(
        "<< /Type /Pages /Kids [{}] /Count {total} >>",
        kids.join(" ")
    ));
    objects.push(
        "<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>"
            .to_owned(),
    );
    objects.push(
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"
            .to_owned(),
    );
    let date = pdf_date(&info.created);
    objects.push(format!(
        "<< /Title {} /Producer {} /Creator {} /CreationDate ({date}) /ModDate ({date}) >>",
        literal(&info.title),
        literal(&info.producer),
        literal(&info.producer),
    ));
    for (index, page) in pages.iter().enumerate() {
        let mut content = String::new();
        let mut y = PAGE_H - MARGIN;
        for (heading, text) in *page {
            let (font, size) = if *heading {
                ("F2", 10.0)
            } else {
                ("F1", BODY_SIZE)
            };
            let _ = writeln!(
                content,
                "BT /{font} {size:.1} Tf {MARGIN:.1} {y:.1} Td {} Tj ET",
                literal(text)
            );
            y -= LEADING;
        }
        let footer = format!("{} — página {} de {}", info.footer, index + 1, total);
        let _ = writeln!(
            content,
            "BT /F1 7.0 Tf {MARGIN:.1} {:.1} Td {} Tj ET",
            MARGIN - 18.0,
            literal(&footer)
        );
        let page_object = first_page + index * 2;
        objects.push(format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W:.0} {PAGE_H:.0}] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {} 0 R >>",
            page_object + 1
        ));
        objects.push(format!(
            "<< /Length {} >>\nstream\n{content}endstream",
            content.len()
        ));
    }

    let mut out: Vec<u8> = b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n".to_vec();
    let mut offsets = Vec::with_capacity(objects.len());
    for (i, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{body}\nendobj\n", i + 1).as_bytes());
    }
    let xref = out.len();
    let mut table = format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1);
    for o in offsets {
        let _ = writeln!(table, "{o:010} 00000 n ");
    }
    let _ = write!(
        table,
        "trailer\n<< /Size {} /Root 1 0 R /Info 5 0 R >>\nstartxref\n{xref}\n%%EOF\n",
        objects.len() + 1
    );
    out.extend_from_slice(table.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> Info {
        Info {
            title: "Relatório".to_owned(),
            producer: "B.O.P.E Scanner 0.10.0".to_owned(),
            created: "2026-10-15T12:00:00Z".to_owned(),
            footer: "B.O.P.E".to_owned(),
        }
    }

    #[test]
    fn a_document_has_a_valid_cross_reference_table_and_every_page() {
        let lines: Vec<Line> = (0..200)
            .map(|i| Line::Text(format!("linha {i} — ação")))
            .collect();
        let pdf = render(&info(), &lines);
        let text = String::from_utf8_lossy(&pdf);
        assert!(pdf.starts_with(b"%PDF-1.4\n"));
        assert!(text.ends_with("%%EOF\n"));
        assert!(text.contains("/Count 3"), "200 lines are three pages");
        // Every xref offset points at the start of its object.
        let start: usize = text
            .rsplit("startxref\n")
            .next()
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!(pdf[start..].starts_with(b"xref"));
        let table = &text[start..];
        for (i, line) in table
            .lines()
            .skip(3)
            .take_while(|l| l.ends_with(" n "))
            .enumerate()
        {
            let offset: usize = line[..10].parse().unwrap();
            assert!(pdf[offset..].starts_with(format!("{} 0 obj", i + 1).as_bytes()));
        }
        assert!(text.contains("CreationDate (D:20261015120000Z)"));
        assert_eq!(
            pdf,
            render(&info(), &lines),
            "the same lines give the same bytes"
        );
    }

    #[test]
    fn text_is_escaped_and_encoded_in_win_ansi() {
        assert_eq!(literal("a(b)c\\"), "(a\\(b\\)c\\\\)");
        assert_eq!(literal("ação"), "(a\\347\\343o)");
        assert_eq!(literal("—"), "(\\227)");
        assert_eq!(literal("ก"), "(?)");
        assert_eq!(literal("x → y"), "(x -> y)");
    }

    #[test]
    fn long_lines_wrap_at_spaces_and_keep_their_indent() {
        let long = format!("    {}", "palavra ".repeat(30));
        let lines = wrap(&long, 40);
        assert!(lines.len() > 3);
        assert!(lines.iter().all(|l| l.chars().count() <= 40));
        assert!(lines[1].starts_with("      "));
        assert_eq!(wrap("curta", 40), vec!["curta".to_owned()]);
        assert!(
            wrap(&"x".repeat(100), 40)
                .iter()
                .all(|l| l.chars().count() <= 40)
        );
    }
}
