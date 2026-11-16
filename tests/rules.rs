use mime_inspect::{Classification, CompressionHint, Detector, Origin, ParseErrorKind};
use mime_inspect::{MAX_CHECKS, MAX_RULE_TEXT_BYTES, MAX_RULES};

fn matched<'a>(detector: &'a Detector, prefix: &[u8]) -> mime_inspect::Match<'a> {
    let Classification::Match(m) = detector.detect(prefix) else {
        panic!("expected match")
    };
    m
}

#[test]
fn comments_escaping_raw_names_and_explicit_hints() {
    let detector = Detector::with_rules(
        " # comment\n0 string =HELLO\\ WORLD greeting:nc ignored description\n!:mime text/x-greeting\n!:compression already-compressed\n",
    ).unwrap();
    let result = matched(&detector, b"HELLO WORLD");
    assert_eq!(result.name, Some("greeting:nc"));
    assert_eq!(result.mime, Some("text/x-greeting"));
    assert_eq!(result.compression_hint, CompressionHint::AlreadyCompressed);
    let no_hint = Detector::with_rules("0 string RAW raw:nc\n").unwrap();
    assert_eq!(
        matched(&no_hint, b"RAW").compression_hint,
        CompressionHint::Unspecified
    );
    let trailing = Detector::with_rules("0 string tail\\ \n").unwrap();
    assert_eq!(matched(&trailing, b"tail ").name, None);
    assert_eq!(trailing.detect(b"tail"), Classification::Unknown);
    let escapes = Detector::with_rules("0 string \\101\\x42\\n\\r\\t\\\\ bytes\n").unwrap();
    assert_eq!(matched(&escapes, b"AB\n\r\t\\").name, Some("bytes"));
}

#[test]
fn all_continuations_are_required_and_the_first_match_wins_without_mime() {
    let detector = Detector::with_rules(
        "0 string ROOT root\n>4 byte 1\n>5 byte 2\n!:mime application/x-root\n",
    )
    .unwrap();
    assert_eq!(matched(&detector, b"ROOT\x01\x02").origin, Origin::Custom);
    for bytes in [
        b"ROOT".as_slice(),
        b"ROOT\x01",
        b"ROOT\x01\x03",
        b"ROOT\0\x02",
    ] {
        assert_eq!(detector.detect(bytes), Classification::Unknown);
    }
    let detector = Detector::with_rules(
        "0 string %PDF- first\n0 string %PDF- second\n!:mime application/x-other\n",
    )
    .unwrap();
    let result = matched(&detector, b"%PDF-");
    assert_eq!(result.name, Some("first"));
    assert_eq!(result.mime, None);
    assert_eq!(result.origin, Origin::Custom);
    assert_eq!(matched(&detector, b"\x1f\x8b").origin, Origin::Builtin);
}

#[test]
fn numeric_equality_endian_masks_and_width_boundaries() {
    for (kind, expected, valid, invalid) in [
        ("byte&0xf0", "=0xa0", b"\xab".as_slice(), b"\x9b".as_slice()),
        (
            "leshort&0xfff0",
            "0x1230",
            b"\x34\x12".as_slice(),
            b"\x12\x34".as_slice(),
        ),
        (
            "beshort&0xfff0",
            "0x1230",
            b"\x12\x34".as_slice(),
            b"\x34\x12".as_slice(),
        ),
        (
            "lelong&0xfffffff0",
            "0x89abcde0",
            b"\xef\xcd\xab\x89".as_slice(),
            b"\x89\xab\xcd\xef".as_slice(),
        ),
        (
            "belong&0xfffffff0",
            "0x89abcde0",
            b"\x89\xab\xcd\xef".as_slice(),
            b"\xef\xcd\xab\x89".as_slice(),
        ),
    ] {
        let detector = Detector::with_rules(&format!("0 {kind} {expected} number\n")).unwrap();
        assert_eq!(matched(&detector, valid).name, Some("number"));
        assert_eq!(detector.detect(invalid), Classification::Unknown);
        for len in 1..valid.len() {
            assert_eq!(detector.detect(&valid[..len]), Classification::Unknown);
        }
        for split in 0..=valid.len() {
            assert_eq!(
                detector.detect_segments(&[&valid[..split], &valid[split..]]),
                detector.detect(valid)
            );
        }
    }
    let detector = Detector::with_rules("0 byte&0xf0 0xa1 no-match\n").unwrap();
    assert_eq!(detector.detect(&[0xa1]), Classification::Unknown);
    let detector = Detector::with_rules("124 belong =4294967295 edge\n").unwrap();
    let mut prefix = [0; 128];
    prefix[124..].fill(255);
    assert_eq!(matched(&detector, &prefix).name, Some("edge"));
    assert_eq!(detector.detect(&prefix[..127]), Classification::Unknown);
    let detector = Detector::with_rules("0 byte 0377 octal\n>01 byte 0x7f\n").unwrap();
    assert_eq!(matched(&detector, &[255, 127]).name, Some("octal"));
}

#[test]
fn malformed_or_unsupported_source_is_atomic_and_diagnostics_are_structural() {
    for (line, kind) in [
        ("0 regex TOKEN name", ParseErrorKind::UnsupportedType),
        ("0 search TOKEN name", ParseErrorKind::UnsupportedType),
        ("0 string/c TOKEN name", ParseErrorKind::UnsupportedType),
        ("0 byte x name", ParseErrorKind::UnsupportedTest),
        ("0 byte >1 name", ParseErrorKind::UnsupportedTest),
        ("0 short 1 name", ParseErrorKind::UnsupportedType),
        (">>1 byte 1", ParseErrorKind::UnsupportedOffset),
        (">&1 byte 1", ParseErrorKind::UnsupportedOffset),
        ("(4.l) byte 1 name", ParseErrorKind::UnsupportedOffset),
        ("128 byte 1", ParseErrorKind::PrefixLimit),
        ("127 string AB", ParseErrorKind::PrefixLimit),
        ("0 byte 256", ParseErrorKind::InvalidLiteral),
        ("0 belong 4294967296", ParseErrorKind::InvalidLiteral),
        ("0 byte&256 1", ParseErrorKind::InvalidLiteral),
        ("0 string \\400", ParseErrorKind::InvalidLiteral),
        ("0 string \\xGG", ParseErrorKind::InvalidLiteral),
        ("0 string =", ParseErrorKind::InvalidLiteral),
        ("!:optional", ParseErrorKind::InvalidFields),
        ("!:strength 1", ParseErrorKind::UnsupportedDirective),
        (
            "!:compression guess",
            ParseErrorKind::InvalidCompressionHint,
        ),
    ] {
        let text =
            format!("0 string PRIVATE_TOKEN initial\n!:mime application/x-initial\n{line}\n");
        let error = Detector::with_rules(&text).unwrap_err();
        assert_eq!(error.line, 3, "{line}");
        assert_eq!(error.kind, kind, "{line}");
        assert!(!error.to_string().contains("PRIVATE_TOKEN"));
        assert!(!format!("{error:?}").contains("PRIVATE_TOKEN"));
    }
    for text in [
        ">1 byte 1",
        "!:mime application/x-orphan",
        "0 string A one\n>1 string B two\n",
        "0 string A one\n!:mime a/b\n!:mime c/d\n",
        "0 string A one\n!:compression unspecified\n!:compression already-compressed\n",
    ] {
        assert!(Detector::with_rules(text).is_err());
    }
}

#[test]
fn count_text_limits_and_generic_missing_metadata_are_explicit() {
    let row = "0 string A\n";
    assert!(Detector::with_rules(&row.repeat(MAX_RULES)).is_ok());
    assert_eq!(
        Detector::with_rules(&row.repeat(MAX_RULES + 1))
            .unwrap_err()
            .kind,
        ParseErrorKind::RuleLimit
    );
    let checks = format!("0 byte 1\n{}", ">1 byte 2\n".repeat(MAX_CHECKS - 1));
    assert!(Detector::with_rules(&checks).is_ok());
    assert_eq!(
        Detector::with_rules(&(checks + ">1 byte 2\n"))
            .unwrap_err()
            .kind,
        ParseErrorKind::CheckLimit
    );
    assert!(Detector::with_rules(&" ".repeat(MAX_RULE_TEXT_BYTES)).is_ok());
    assert_eq!(
        Detector::with_rules(&" ".repeat(MAX_RULE_TEXT_BYTES + 1))
            .unwrap_err()
            .kind,
        ParseErrorKind::TextLimit
    );
    let detector = Detector::with_rules(row).unwrap();
    let m = matched(&detector, b"A");
    assert_eq!((m.name, m.mime), (None, None));
    assert_eq!(detector.detect_segments(&[&[], &[]]), Classification::Empty);
}
