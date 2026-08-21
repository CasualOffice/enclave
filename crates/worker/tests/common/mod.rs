//! PDFs assembled byte by byte, shared by the two test binaries that need one.
//!
//! Assembled rather than committed, for the reason `crates/indexing/tests/pdf.rs` gives about its
//! own builders: a binary fixture is content nobody reviews in a diff, and one whose expected text
//! is a claim about a file rather than something the test constructed.
//!
//! Shared rather than copied because a fixture builder duplicated across two files is two things to
//! keep in step, and the day they disagree the test that is wrong is the one nobody re-read.

// Each test binary includes the whole module and uses part of it.
#![allow(dead_code)]

/// One US-Letter page whose content stream is `content`, with Helvetica available as `/F1`.
///
/// The cross-reference table is written properly, with real byte offsets. PDFium would rebuild a
/// broken one, which is precisely why it is not left broken — a test whose input only works because
/// the parser repaired it is a test of the repair.
pub(crate) fn one_page_pdf(content: &str) -> Vec<u8> {
    let objects = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_owned(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R \
         >> >> /Contents 4 0 R >>"
            .to_owned(),
        format!("<< /Length {} >>\nstream\n{content}\nendstream", content.len()),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_owned(),
    ];

    let mut pdf = Vec::from(&b"%PDF-1.4\n"[..]);
    let mut offsets = Vec::new();
    for (index, body) in objects.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.extend_from_slice(format!("{} 0 obj\n{body}\nendobj\n", index + 1).as_bytes());
    }

    let startxref = pdf.len();
    pdf.extend_from_slice(format!("xref\n0 {}\n", objects.len() + 1).as_bytes());
    pdf.extend_from_slice(b"0000000000 65535 f \n");
    for offset in &offsets {
        pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    pdf.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{startxref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    pdf
}

/// A page carrying two very large words, so what OCR reads is not a question about font sizes.
pub(crate) fn page_of_words() -> Vec<u8> {
    one_page_pdf("BT /F1 96 Tf 60 560 Td (INVOICE) Tj 0 -160 Td (TOTAL) Tj ET")
}

/// A page with nothing drawn on it.
pub(crate) fn blank_page() -> Vec<u8> {
    one_page_pdf("")
}
