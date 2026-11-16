use mime_inspect::{
    BUILTIN_PATTERN_COUNT, Classification, CompressionHint, Detector, MAX_PREFIX_BYTES, Origin,
};

fn mime(detector: &Detector, bytes: &[u8]) -> Option<String> {
    match detector.detect(bytes) {
        Classification::Match(m) => m.mime.map(str::to_owned),
        Classification::Empty | Classification::Unknown => None,
    }
}

#[test]
fn empty_unknown_and_borrowing_are_explicit() {
    let detector = Detector::new();
    assert_eq!(detector.detect(b""), Classification::Empty);
    assert_eq!(detector.detect(b"ordinary prose"), Classification::Unknown);
    let result = {
        let input = b"%PDF-1.7".to_vec();
        detector.detect(&input)
    };
    let Classification::Match(m) = result else {
        panic!("expected match")
    };
    assert_eq!(m.mime, Some("application/pdf"));
    assert_eq!(m.compression_hint, CompressionHint::Unspecified);
    assert_eq!(m.origin, Origin::Builtin);
}

#[test]
fn supported_catalog_branches_and_every_segment_split() {
    let detector = Detector::default();
    let cases: &[(&[u8], &str)] = &[
        (b"\x1f\x8b", "application/gzip"),
        (b"BZh", "application/x-bzip2"),
        (b"Rar!", "application/vnd.rar"),
        (b"\x1f\x9d", "application/x-compress"),
        (b"%PDF-", "application/pdf"),
        (b"\x89PNG\r\n\x1a\n", "image/png"),
        (b"GIF8", "image/gif"),
        (b"\xff\xd8", "image/jpeg"),
        (b"MM\0*", "image/tiff"),
        (b"II*\0", "image/tiff"),
        (b"8BPS", "image/vnd.adobe.photoshop"),
        (b"fLaC", "audio/flac"),
        (b"OggS", "application/ogg"),
        (b"\x8aMNG", "video/x-mng"),
        (b"....moov", "video/quicktime"),
        (b"....mdat", "video/quicktime"),
        (b"....jP", "image/jp2"),
        (b"ID3", "audio/mpeg"),
        (b"\0\0\x01\xba", "video/mpeg"),
        (b"\0\0\x01\xb3", "video/mpeg"),
        (b"....................\xdc\xa7\xc4\xfd", "application/x-zoo"),
        (b"..-lzs-", "application/x-lha"),
        (b"..-lh -", "application/x-lha"),
        (b"..-lhd-", "application/x-lha"),
        (b"..-lh2-", "application/x-lha"),
        (b"..-lh3-", "application/x-lha"),
        (b"..-lh4-", "application/x-lha"),
        (b"..-lh5-", "application/x-lha"),
        (b"..-lh6-", "application/x-lha"),
        (b"..-lh7-", "application/x-lha"),
        (b"PK\x03\x04", "application/zip"),
        (b"BM", "image/bmp"),
        (b"\xfd7zXZ\0", "application/x-xz"),
        (b"\x28\xb5\x2f\xfd", "application/zstd"),
        (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"),
        (b"RIFF....WEBP", "image/webp"),
        (b"RIFF....WAVE", "audio/wav"),
        (b"RIFF....AVI ", "video/x-msvideo"),
        (b"....ftypisom", "video/mp4"),
        (b"....ftypmp41", "video/mp4"),
        (b"....ftypmp42", "video/mp4"),
        (b"....ftypmmp4", "video/mp4"),
        (b"....ftypM4V", "video/mp4"),
        (b"....ftypM4A", "audio/mp4"),
        (b"....ftypjp2", "image/jp2"),
        (b"....ftypqt", "video/quicktime"),
        (b"\xff\xfb\x90", "audio/mpeg"),
    ];
    assert_eq!(cases.len(), BUILTIN_PATTERN_COUNT);
    assert_eq!(BUILTIN_PATTERN_COUNT, 47);
    for &(bytes, expected) in cases {
        let detection = detector.detect(bytes);
        assert_eq!(
            mime(&detector, bytes).as_deref(),
            Some(expected),
            "{bytes:?}"
        );
        for first in 0..=bytes.len() {
            for second in first..=bytes.len() {
                assert_eq!(
                    detector.detect_segments(&[
                        &bytes[..first],
                        &[],
                        &bytes[first..second],
                        &[],
                        &bytes[second..]
                    ]),
                    detection
                );
            }
        }
        for len in 1..bytes.len() {
            assert_eq!(
                detector.detect(&bytes[..len]),
                Classification::Unknown,
                "{bytes:?} len {len}"
            );
        }
        let bound = detector.match_bounds();
        let Classification::Match(m) = detection else {
            unreachable!()
        };
        assert!(m.mime.unwrap().len() <= bound.mime_bytes);
        assert!(m.name.unwrap().len() <= bound.name_bytes);
    }
}

#[test]
fn compression_hints_do_not_turn_into_container_policy() {
    let detector = Detector::new();
    for bytes in [
        b"%PDF-".as_slice(),
        b"II*\0",
        b"PK\x03\x04",
        b"Rar!",
        b"RIFF....AVI ",
        b"....ftypisom",
    ] {
        let Classification::Match(m) = detector.detect(bytes) else {
            panic!("expected known container")
        };
        assert_eq!(m.compression_hint, CompressionHint::Unspecified);
    }
    for bytes in [
        b"\x1f\x8b".as_slice(),
        b"\x89PNG\r\n\x1a\n",
        b"\xfd7zXZ\0",
        b"\x28\xb5\x2f\xfd",
        b"RIFF....WEBP",
    ] {
        let Classification::Match(m) = detector.detect(bytes) else {
            panic!("expected compressed format")
        };
        assert_eq!(m.compression_hint, CompressionHint::AlreadyCompressed);
    }
}

#[test]
fn builtin_compound_signatures_require_each_marker_and_correct_case() {
    let detector = Detector::new();
    for bytes in [
        b"RIFF".as_slice(),
        b"....WAVE",
        b"RIFX....AVI ",
        b"riff....WEBP",
        b"....FTYPisom",
        b"....ftypISOM",
        b"\xff\xfb\x00",
        b"\xff\xfb\xf0",
    ] {
        assert_eq!(detector.detect(bytes), Classification::Unknown, "{bytes:?}");
    }
    let mut prefix = vec![0; MAX_PREFIX_BYTES];
    prefix.extend_from_slice(b"%PDF-");
    assert_eq!(detector.detect(&prefix), Classification::Unknown);
    assert_eq!(
        detector.detect_segments(&[&prefix[..128], &prefix[128..]]),
        Classification::Unknown
    );
}
