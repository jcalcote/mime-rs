// Selected signature facts adapted from simplemagic 1.17's public magic file.
// Copyright 2021, Gray Watson. ISC notice: resources/simplemagic-LICENSE.txt.
// See resources/signature-sources.json for pinned public source hashes/coverage.
// The entire upstream database and its general rule semantics are not included.

use crate::{CompressionHint, Match, Origin};
use CompressionHint::{AlreadyCompressed as Compressed, Unspecified};

type Signature = (
    usize,
    &'static [u8],
    &'static str,
    &'static str,
    CompressionHint,
);

const SIGNATURES: &[Signature] = &[
    (0, b"\x1f\x8b", "application/gzip", "gzip", Compressed),
    (0, b"BZh", "application/x-bzip2", "bzip2", Compressed),
    (0, b"Rar!", "application/vnd.rar", "rar", Unspecified),
    (
        0,
        b"\x1f\x9d",
        "application/x-compress",
        "compress",
        Compressed,
    ),
    (0, b"%PDF-", "application/pdf", "pdf", Unspecified),
    (0, b"\x89PNG\r\n\x1a\n", "image/png", "png", Compressed),
    (0, b"GIF8", "image/gif", "gif", Compressed),
    (0, b"\xff\xd8", "image/jpeg", "jpeg", Compressed),
    (0, b"MM\x00\x2a", "image/tiff", "tiff", Unspecified),
    (0, b"II\x2a\x00", "image/tiff", "tiff", Unspecified),
    (
        0,
        b"8BPS",
        "image/vnd.adobe.photoshop",
        "photoshop",
        Unspecified,
    ),
    (0, b"fLaC", "audio/flac", "flac", Compressed),
    (0, b"OggS", "application/ogg", "ogg", Unspecified),
    (0, b"\x8aMNG", "video/x-mng", "mng", Compressed),
    (4, b"moov", "video/quicktime", "quicktime", Unspecified),
    (4, b"mdat", "video/quicktime", "quicktime", Unspecified),
    (4, b"jP", "image/jp2", "jp2", Compressed),
    (0, b"ID3", "audio/mpeg", "mp3", Compressed),
    (0, b"\x00\x00\x01\xba", "video/mpeg", "mpeg", Compressed),
    (0, b"\x00\x00\x01\xb3", "video/mpeg", "mpeg", Compressed),
    (
        20,
        b"\xdc\xa7\xc4\xfd",
        "application/x-zoo",
        "zoo",
        Unspecified,
    ),
    (2, b"-lzs-", "application/x-lha", "lha", Unspecified),
    (2, b"-lh -", "application/x-lha", "lha", Unspecified),
    (2, b"-lhd-", "application/x-lha", "lha", Unspecified),
    (2, b"-lh2-", "application/x-lha", "lha", Unspecified),
    (2, b"-lh3-", "application/x-lha", "lha", Unspecified),
    (2, b"-lh4-", "application/x-lha", "lha", Unspecified),
    (2, b"-lh5-", "application/x-lha", "lha", Unspecified),
    (2, b"-lh6-", "application/x-lha", "lha", Unspecified),
    (2, b"-lh7-", "application/x-lha", "lha", Unspecified),
    (0, b"PK\x03\x04", "application/zip", "zip", Unspecified),
    (0, b"BM", "image/bmp", "bmp", Unspecified),
    // Additional public format signatures; not copied from a service rule file.
    (0, b"\xfd7zXZ\x00", "application/x-xz", "xz", Compressed),
    (
        0,
        b"\x28\xb5\x2f\xfd",
        "application/zstd",
        "zstd",
        Compressed,
    ),
    (
        0,
        b"7z\xbc\xaf\x27\x1c",
        "application/x-7z-compressed",
        "7zip",
        Unspecified,
    ),
];

const RIFF: &[(&[u8], &str, &str, CompressionHint)] = &[
    (b"WEBP", "image/webp", "webp", Compressed),
    (b"WAVE", "audio/wav", "wav", Unspecified),
    (b"AVI ", "video/x-msvideo", "avi", Unspecified),
];

const BRANDS: &[(&[u8], &str, &str, CompressionHint)] = &[
    (b"isom", "video/mp4", "mp4", Unspecified),
    (b"mp41", "video/mp4", "mp4", Unspecified),
    (b"mp42", "video/mp4", "mp4", Unspecified),
    (b"mmp4", "video/mp4", "mp4", Unspecified),
    (b"M4V", "video/mp4", "mp4", Unspecified),
    (b"M4A", "audio/mp4", "m4a", Unspecified),
    (b"jp2", "image/jp2", "jp2", Compressed),
    (b"qt", "video/quicktime", "quicktime", Unspecified),
];

pub(crate) const PATTERN_COUNT: usize = SIGNATURES.len() + RIFF.len() + BRANDS.len() + 1;

fn found(
    mime: &'static str,
    name: &'static str,
    compression_hint: CompressionHint,
) -> Match<'static> {
    Match {
        mime: Some(mime),
        name: Some(name),
        origin: Origin::Builtin,
        compression_hint,
    }
}

pub(crate) fn detect(prefix: &[u8]) -> Option<Match<'static>> {
    if prefix.starts_with(b"RIFF") {
        for &(kind, mime, name, hint) in RIFF {
            if prefix.get(8..12) == Some(kind) {
                return Some(found(mime, name, hint));
            }
        }
    }
    if prefix.get(4..8) == Some(b"ftyp") {
        if let Some(brand) = prefix.get(8..) {
            for &(bytes, mime, name, hint) in BRANDS {
                if brand.starts_with(bytes) {
                    return Some(found(mime, name, hint));
                }
            }
        }
    }
    // MPEG layer III sync, version and non-reserved bitrate nibble.
    if prefix.first() == Some(&0xff)
        && prefix.get(1).is_some_and(|byte| byte & 0xfe == 0xfa)
        && prefix
            .get(2)
            .is_some_and(|byte| (0x10..=0xe0).contains(&(byte & 0xf0)))
    {
        return Some(found("audio/mpeg", "mp3", Compressed));
    }
    SIGNATURES
        .iter()
        .find_map(|&(offset, bytes, mime, name, hint)| {
            (prefix.get(offset..offset + bytes.len()) == Some(bytes))
                .then(|| found(mime, name, hint))
        })
}

pub(crate) fn bounds() -> (usize, usize) {
    SIGNATURES
        .iter()
        .map(|&(_, _, mime, name, _)| (mime, name))
        .chain(
            RIFF.iter()
                .chain(BRANDS)
                .map(|&(_, mime, name, _)| (mime, name)),
        )
        .chain(std::iter::once(("audio/mpeg", "mp3")))
        .fold((0, 0), |(mime, name), (m, n)| {
            (mime.max(m.len()), name.max(n.len()))
        })
}
