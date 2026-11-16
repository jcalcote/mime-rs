use std::alloc::Layout;

use crate::{Classification, CompressionHint, Match, Origin};

/// Checked sizing or copy-plan mismatch, without input text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CopyError {
    /// A requested layout or checked aggregate cannot be represented.
    SizeOverflow,
    /// Classification variant, string presence or lengths differ from the plan.
    PlanMismatch,
}
impl std::fmt::Display for CopyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::SizeOverflow => "classification allocation size overflow",
            Self::PlanMismatch => "classification copy plan mismatch",
        })
    }
}
impl std::error::Error for CopyError {}

/// Conservative compiler peak before parsing, excluding borrowed source text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompilePlan {
    /// Peak requested bytes, including temporary/final allocation overlap.
    pub peak_bytes: usize,
    /// Conservative peak allocation count, for caller allocator allowances.
    pub peak_allocations: usize,
}

/// Independent string maxima for every possible detector result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatchBounds {
    /// Maximum MIME UTF-8 bytes; may originate in a different rule than `name_bytes`.
    pub mime_bytes: usize,
    /// Maximum name UTF-8 bytes.
    pub name_bytes: usize,
}
impl MatchBounds {
    /// Nonzero allocation request bounds, not an executable exact copy plan.
    ///
    /// # Errors
    /// Rejects unrepresentable caller-constructed bounds.
    pub fn allocation_layouts(self) -> Result<impl Iterator<Item = Layout>, CopyError> {
        Ok([layout(self.mime_bytes)?, layout(self.name_bytes)?]
            .into_iter()
            .filter(|l| l.size() != 0))
    }

    /// Checked maximum retained string bytes, excluding owner/allocator overhead.
    ///
    /// # Errors
    /// Rejects overflow or invalid allocation layouts.
    pub fn retained_bytes(self) -> Result<usize, CopyError> {
        layout(self.mime_bytes)?;
        layout(self.name_bytes)?;
        self.mime_bytes
            .checked_add(self.name_bytes)
            .ok_or(CopyError::SizeOverflow)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Empty,
    Unknown,
    Match,
}

/// Exact requested string copy storage; no admission or allocation happens here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CopyPlan {
    kind: Kind,
    mime: Option<Layout>,
    name: Option<Layout>,
    bytes: usize,
}

fn layout(len: usize) -> Result<Layout, CopyError> {
    Layout::array::<u8>(len).map_err(|_| CopyError::SizeOverflow)
}

impl Classification<'_> {
    /// Plan an independent owned copy, without retaining this value's lifetime.
    ///
    /// # Errors
    /// Rejects any unrepresentable allocation layout or aggregate.
    pub fn copy_plan(self) -> Result<CopyPlan, CopyError> {
        let (kind, mime, name) = match self {
            Self::Empty => (Kind::Empty, None, None),
            Self::Unknown => (Kind::Unknown, None, None),
            Self::Match(m) => (Kind::Match, m.mime.map(str::len), m.name.map(str::len)),
        };
        let mime = mime.map(layout).transpose()?;
        let name = name.map(layout).transpose()?;
        let bytes = mime
            .map_or(0, |l| l.size())
            .checked_add(name.map_or(0, |l| l.size()))
            .ok_or(CopyError::SizeOverflow)?;
        Ok(CopyPlan {
            kind,
            mime,
            name,
            bytes,
        })
    }
}

impl CopyPlan {
    /// Exact retained string bytes; no inline owner or allocator overhead.
    #[must_use]
    pub fn retained_bytes(self) -> usize {
        self.bytes
    }

    /// Exact nonzero string allocation requests; empty strings request nothing.
    pub fn allocation_layouts(self) -> impl Iterator<Item = Layout> {
        [self.mime, self.name]
            .into_iter()
            .flatten()
            .filter(|l| l.size() != 0)
    }

    /// Copy after the caller has arranged ownership/funding for this plan.
    ///
    /// # Errors
    /// Rejects shape/length mismatch before allocating. Equal-shaped values of
    /// the same string lengths have the same costs; contents/flags are not bound.
    pub fn copy(
        self,
        classification: Classification<'_>,
    ) -> Result<OwnedClassification, CopyError> {
        if self != classification.copy_plan()? {
            return Err(CopyError::PlanMismatch);
        }
        Ok(match classification {
            Classification::Empty => OwnedClassification::Empty,
            Classification::Unknown => OwnedClassification::Unknown,
            Classification::Match(m) => OwnedClassification::Match(OwnedMatch {
                mime: m.mime.map(Into::into),
                name: m.name.map(Into::into),
                origin: m.origin,
                compression_hint: m.compression_hint,
            }),
        })
    }
}

/// Independent owned result. Explicit copying avoids hidden per-call allocation.
#[derive(Debug, Eq, PartialEq)]
pub enum OwnedClassification {
    /// Empty prefix, without a string allocation.
    Empty,
    /// No recognized signature, without a string allocation.
    Unknown,
    /// Owned match metadata.
    Match(OwnedMatch),
}

/// Owned match strings, independent of source and detector lifetime.
#[derive(Debug, Eq, PartialEq)]
pub struct OwnedMatch {
    mime: Option<Box<str>>,
    name: Option<Box<str>>,
    origin: Origin,
    compression_hint: CompressionHint,
}

impl OwnedClassification {
    /// Borrow the original classification shape from this owner.
    #[must_use]
    pub fn as_borrowed(&self) -> Classification<'_> {
        match self {
            Self::Empty => Classification::Empty,
            Self::Unknown => Classification::Unknown,
            Self::Match(m) => Classification::Match(Match {
                mime: m.mime.as_deref(),
                name: m.name.as_deref(),
                origin: m.origin,
                compression_hint: m.compression_hint,
            }),
        }
    }

    /// Exact nonzero requested string allocations, excluding this owner's storage.
    pub fn retained_allocations(&self) -> impl Iterator<Item = Layout> {
        let strings = match self {
            Self::Match(m) => [m.mime.as_deref(), m.name.as_deref()],
            Self::Empty | Self::Unknown => [None, None],
        };
        strings
            .into_iter()
            .flatten()
            .map(Layout::for_value)
            .filter(|l| l.size() != 0)
    }
}
