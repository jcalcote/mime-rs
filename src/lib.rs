//! Bounded signature detection and reusable custom magic rules.
//!
//! Detection borrows immutable rules, never input bytes, and allocates nothing.
//! This is a deliberately small magic grammar, not a libmagic implementation.
//!
//! ```
//! use mime_inspect::{Classification, Detector};
//! let detector = Detector::new();
//! match detector.detect(b"\x89PNG\r\n\x1a\n") {
//!     Classification::Match(found) => assert_eq!(found.mime, Some("image/png")),
//!     other => panic!("unexpected classification: {other:?}"),
//! }
//! ```
#![cfg_attr(not(test), forbid(unsafe_code))]

mod catalog;
mod error;
mod owned;
mod rules;

pub use error::{ParseError, ParseErrorKind};
pub use owned::{CompilePlan, CopyError, CopyPlan, MatchBounds, OwnedClassification, OwnedMatch};

/// Maximum number of leading source bytes inspected.
pub const MAX_PREFIX_BYTES: usize = 128;
/// Maximum UTF-8 custom magic source size.
pub const MAX_RULE_TEXT_BYTES: usize = 64 * 1024;
/// Maximum top-level custom groups.
pub const MAX_RULES: usize = 256;
/// Maximum total predicates across custom groups.
pub const MAX_CHECKS: usize = 1024;
/// Independent builtin signature branches, not a count of validated formats.
pub const BUILTIN_PATTERN_COUNT: usize = catalog::PATTERN_COUNT;

/// Origin of a successful signature match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Origin {
    /// The compiled static signature catalog.
    Builtin,
    /// A caller-supplied rule group.
    Custom,
}

/// Advisory format metadata, independent of application compression policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CompressionHint {
    /// No assertion about compression; unknown does not mean compressible.
    #[default]
    Unspecified,
    /// The signature or explicit custom annotation suggests compressed data.
    AlreadyCompressed,
}

/// Borrowed match metadata. Strings outlive the input and borrow the detector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Match<'a> {
    /// MIME metadata, if the matching rule supplies it.
    pub mime: Option<&'a str>,
    /// Literal short name, if the matching rule supplies it.
    pub name: Option<&'a str>,
    /// Catalog or custom rule origin.
    pub origin: Origin,
    /// Advisory metadata; never an instruction to compress or bypass.
    pub compression_hint: CompressionHint,
}

/// Result of inspecting a leading source prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Classification<'a> {
    /// The supplied prefix is empty.
    Empty,
    /// No supported signature matched.
    Unknown,
    /// A signature matched; this does not validate the complete format.
    Match(Match<'a>),
}

/// Immutable detector: custom rules precede the static builtin catalog.
///
/// A custom match without a MIME is still a match. All checks in a group must
/// succeed, and the first successful group wins. No filesystem or global state
/// is consulted. Share one detector across calls or threads without cloning it.
#[derive(Default)]
pub struct Detector {
    rules: rules::Rules,
}

impl std::fmt::Debug for Detector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Detector")
            .field("custom_groups", &self.rules.len())
            .finish_non_exhaustive()
    }
}

impl Detector {
    /// Builtin-only detector. Construction allocates nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Compile caller-supplied custom rules once, with builtin fallback on no match.
    ///
    /// Unlike a failed match, a parse failure is an explicit error: no partial
    /// rule set or implicit fallback detector is returned.
    ///
    /// # Errors
    /// Returns a structural, line-numbered error without raw input text.
    pub fn with_rules(text: &str) -> Result<Self, ParseError> {
        Ok(Self {
            rules: rules::Rules::parse(text)?,
        })
    }

    /// Inspect at most 128 bytes beginning at source offset zero.
    ///
    /// Returned strings borrow this detector, not `prefix`. A short prefix can
    /// miss a signature that requires more bytes; this API performs no reads.
    #[must_use]
    pub fn detect(&self, prefix: &[u8]) -> Classification<'_> {
        let prefix = &prefix[..prefix.len().min(MAX_PREFIX_BYTES)];
        if prefix.is_empty() {
            return Classification::Empty;
        }
        self.rules
            .find_match(prefix)
            .or_else(|| catalog::detect(prefix))
            .map_or(Classification::Unknown, Classification::Match)
    }

    /// Inspect contiguous, ordered segments beginning at source offset zero.
    ///
    /// Copies at most 128 bytes into stack storage and allocates nothing. Empty
    /// segments are allowed; work includes visiting supplied empty descriptors.
    #[must_use]
    pub fn detect_segments(&self, segments: &[&[u8]]) -> Classification<'_> {
        let mut prefix = [0; MAX_PREFIX_BYTES];
        let mut len = 0;
        for segment in segments {
            let count = segment.len().min(MAX_PREFIX_BYTES - len);
            prefix[len..len + count].copy_from_slice(&segment[..count]);
            len += count;
            if len == MAX_PREFIX_BYTES {
                break;
            }
        }
        self.detect(&prefix[..len])
    }

    /// Exact nonzero requested allocations retained for compiled custom rules.
    ///
    /// Excludes this object's inline storage, allocator overhead and caller
    /// sharing/control wrappers. A builtin-only detector has no such allocations.
    pub fn retained_allocations(&self) -> impl Iterator<Item = std::alloc::Layout> + '_ {
        self.rules.allocations()
    }

    /// Conservative maxima for any match from this detector, before source I/O.
    #[must_use]
    pub fn match_bounds(&self) -> MatchBounds {
        let (builtin_mime, builtin_name) = catalog::bounds();
        let (custom_mime, custom_name) = self.rules.bounds();
        MatchBounds {
            mime_bytes: builtin_mime.max(custom_mime),
            name_bytes: builtin_name.max(custom_name),
        }
    }

    /// Checked compiler peak, excluding caller-owned rule text and owner storage.
    ///
    /// # Errors
    /// Returns `SizeOverflow` if a platform cannot represent a required layout.
    pub fn compile_plan() -> Result<CompilePlan, CopyError> {
        rules::compile_plan()
    }
}

#[cfg(test)]
mod allocation_tests;
