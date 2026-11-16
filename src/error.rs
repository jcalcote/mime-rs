/// Structural custom-rule parse error. Never retains raw input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseError {
    /// One-based source line; zero denotes a whole-source size limit.
    pub line: usize,
    /// Structural failure category.
    pub kind: ParseErrorKind,
}

/// Supported grammar failures; unknown forms are never silently ignored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ParseErrorKind {
    /// Source exceeds 64 KiB.
    TextLimit,
    /// More than 256 top-level groups.
    RuleLimit,
    /// More than 1,024 total checks.
    CheckLimit,
    /// Required tokens are missing or a continuation/directive has no parent.
    InvalidFields,
    /// Nested continuations or relative/indirect offsets are unsupported.
    UnsupportedOffset,
    /// An offset or its complete predicate exceeds the 128-byte profile.
    PrefixLimit,
    /// Type is outside the documented equality subset.
    UnsupportedType,
    /// Operators or wildcards are outside the documented equality subset.
    UnsupportedTest,
    /// A numeric value, mask, string escape or empty literal is invalid.
    InvalidLiteral,
    /// The directive is outside the documented metadata subset.
    UnsupportedDirective,
    /// A metadata declaration is repeated within a group.
    DuplicateMetadata,
    /// A compression annotation has an unsupported value.
    InvalidCompressionHint,
    /// A name is not a literal token or conflicts with another group name.
    InvalidName,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "magic rule line {}: {:?}", self.line, self.kind)
    }
}

impl std::error::Error for ParseError {}
