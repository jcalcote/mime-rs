use std::alloc::Layout;

use crate::{CompilePlan, CompressionHint, CopyError, Match, Origin, ParseError, ParseErrorKind};
use crate::{MAX_CHECKS, MAX_PREFIX_BYTES, MAX_RULE_TEXT_BYTES, MAX_RULES};

#[derive(Debug)]
enum Predicate {
    Bytes(Box<[u8]>),
    Number {
        width: usize,
        big_endian: bool,
        mask: u32,
        expected: u32,
    },
}

#[derive(Debug)]
struct Check {
    offset: usize,
    predicate: Predicate,
}

impl Check {
    fn matches(&self, prefix: &[u8]) -> bool {
        match &self.predicate {
            Predicate::Bytes(bytes) => {
                prefix.get(self.offset..self.offset + bytes.len()) == Some(bytes.as_ref())
            }
            Predicate::Number {
                width,
                big_endian,
                mask,
                expected,
            } => {
                let Some(bytes) = prefix.get(self.offset..self.offset + width) else {
                    return false;
                };
                let value = if *big_endian {
                    bytes.iter().fold(0_u32, |v, b| (v << 8) | u32::from(*b))
                } else {
                    bytes
                        .iter()
                        .rev()
                        .fold(0_u32, |v, b| (v << 8) | u32::from(*b))
                };
                value & mask == *expected
            }
        }
    }
}

#[derive(Debug, Default)]
struct Rule {
    checks: Box<[Check]>,
    name: Option<Box<str>>,
    mime: Option<Box<str>>,
    hint: Option<CompressionHint>,
}

#[derive(Default)]
pub(crate) struct Rules {
    rules: Box<[Rule]>,
}

impl Rules {
    pub(crate) fn len(&self) -> usize {
        self.rules.len()
    }

    pub(crate) fn parse(text: &str) -> Result<Self, ParseError> {
        if text.len() > MAX_RULE_TEXT_BYTES {
            return Err(ParseError {
                line: 0,
                kind: ParseErrorKind::TextLimit,
            });
        }
        let mut rules = Vec::<Rule>::new();
        let mut checks = Vec::<Check>::new();
        let mut total = 0;
        for (index, raw) in text.lines().enumerate() {
            let line = raw.trim_start();
            let fail = |kind| ParseError {
                line: index + 1,
                kind,
            };
            if line.trim_end().is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with("!:") {
                let rule = rules
                    .last_mut()
                    .ok_or_else(|| fail(ParseErrorKind::InvalidFields))?;
                metadata(rule, line).map_err(fail)?;
                continue;
            }
            if line.starts_with(">>") {
                return Err(fail(ParseErrorKind::UnsupportedOffset));
            }
            let continuation = line.starts_with('>');
            if continuation && rules.is_empty() {
                return Err(fail(ParseErrorKind::InvalidFields));
            }
            if !continuation {
                if let Some(previous) = rules.last_mut() {
                    previous.checks = std::mem::take(&mut checks).into_boxed_slice();
                }
                if rules.len() == MAX_RULES {
                    return Err(fail(ParseErrorKind::RuleLimit));
                }
                rules.push(Rule::default());
            }
            total += 1;
            if total > MAX_CHECKS {
                return Err(fail(ParseErrorKind::CheckLimit));
            }
            let (check, name) =
                parse_check(line.strip_prefix('>').unwrap_or(line)).map_err(fail)?;
            if let Some(name) = name {
                let rule = rules
                    .last_mut()
                    .ok_or_else(|| fail(ParseErrorKind::InvalidFields))?;
                if let Some(previous) = rule.name.as_deref() {
                    if previous != name {
                        return Err(fail(ParseErrorKind::InvalidName));
                    }
                }
                rule.name = Some(name.into());
            }
            checks.push(check);
        }
        if let Some(previous) = rules.last_mut() {
            previous.checks = checks.into_boxed_slice();
        }
        Ok(Self {
            rules: rules.into_boxed_slice(),
        })
    }

    pub(crate) fn find_match(&self, prefix: &[u8]) -> Option<Match<'_>> {
        self.rules
            .iter()
            .find(|rule| rule.checks.iter().all(|check| check.matches(prefix)))
            .map(|rule| Match {
                mime: rule.mime.as_deref(),
                name: rule.name.as_deref(),
                origin: Origin::Custom,
                compression_hint: rule.hint.unwrap_or_default(),
            })
    }

    pub(crate) fn allocations(&self) -> impl Iterator<Item = Layout> + '_ {
        std::iter::once(Layout::for_value(self.rules.as_ref()))
            .chain(self.rules.iter().flat_map(|rule| {
                [
                    Layout::for_value(rule.checks.as_ref()),
                    Layout::for_value(rule.name.as_deref().unwrap_or("")),
                    Layout::for_value(rule.mime.as_deref().unwrap_or("")),
                ]
                .into_iter()
                .chain(rule.checks.iter().filter_map(
                    |check| match &check.predicate {
                        Predicate::Bytes(bytes) => Some(Layout::for_value(bytes.as_ref())),
                        Predicate::Number { .. } => None,
                    },
                ))
            }))
            .filter(|layout| layout.size() != 0)
    }

    pub(crate) fn bounds(&self) -> (usize, usize) {
        self.rules.iter().fold((0, 0), |(mime, name), rule| {
            (
                mime.max(rule.mime.as_deref().map_or(0, str::len)),
                name.max(rule.name.as_deref().map_or(0, str::len)),
            )
        })
    }
}

fn metadata(rule: &mut Rule, line: &str) -> Result<(), ParseErrorKind> {
    let mut fields = line.split_whitespace();
    let key = fields.next().ok_or(ParseErrorKind::InvalidFields)?;
    let value = fields.next().ok_or(ParseErrorKind::InvalidFields)?;
    if fields.next().is_some() {
        return Err(ParseErrorKind::InvalidFields);
    }
    match key {
        "!:mime" => {
            if rule.mime.is_some() {
                return Err(ParseErrorKind::DuplicateMetadata);
            }
            rule.mime = Some(value.into());
        }
        "!:compression" => {
            if rule.hint.is_some() {
                return Err(ParseErrorKind::DuplicateMetadata);
            }
            rule.hint = Some(match value {
                "already-compressed" => CompressionHint::AlreadyCompressed,
                "unspecified" => CompressionHint::Unspecified,
                _ => return Err(ParseErrorKind::InvalidCompressionHint),
            });
        }
        _ => return Err(ParseErrorKind::UnsupportedDirective),
    }
    Ok(())
}

fn parse_check(line: &str) -> Result<(Check, Option<&str>), ParseErrorKind> {
    let (offset, rest) = token(line).ok_or(ParseErrorKind::InvalidFields)?;
    let (kind, rest) = token(rest).ok_or(ParseErrorKind::InvalidFields)?;
    let (literal, rest) = token(rest).ok_or(ParseErrorKind::InvalidFields)?;
    let name = rest.split_whitespace().next();
    if let Some(name) = name {
        if !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
        {
            return Err(ParseErrorKind::InvalidName);
        }
    }
    let offset = number(offset)
        .and_then(|n| usize::try_from(n).ok())
        .ok_or(ParseErrorKind::UnsupportedOffset)?;
    let (predicate, width) = if kind == "string" {
        if unsupported_test(literal) {
            return Err(ParseErrorKind::UnsupportedTest);
        }
        let bytes = decode(literal.strip_prefix('=').unwrap_or(literal))?.into_boxed_slice();
        if bytes.is_empty() {
            return Err(ParseErrorKind::InvalidLiteral);
        }
        let width = bytes.len();
        (Predicate::Bytes(bytes), width)
    } else {
        numeric(kind, literal)?
    };
    if offset >= MAX_PREFIX_BYTES || width > MAX_PREFIX_BYTES - offset {
        return Err(ParseErrorKind::PrefixLimit);
    }
    Ok((Check { offset, predicate }, name))
}

fn unsupported_test(literal: &str) -> bool {
    literal == "x" || literal.starts_with(['!', '<', '>', '&', '^', '~'])
}

fn numeric(kind: &str, literal: &str) -> Result<(Predicate, usize), ParseErrorKind> {
    let (kind, mask) = kind
        .split_once('&')
        .map_or((kind, None), |(k, m)| (k, Some(m)));
    let (width, big_endian, maximum) = match kind {
        "byte" => (1, false, u32::from(u8::MAX)),
        "leshort" => (2, false, u32::from(u16::MAX)),
        "beshort" => (2, true, u32::from(u16::MAX)),
        "lelong" => (4, false, u32::MAX),
        "belong" => (4, true, u32::MAX),
        _ => return Err(ParseErrorKind::UnsupportedType),
    };
    if unsupported_test(literal) {
        return Err(ParseErrorKind::UnsupportedTest);
    }
    let parse = |text| {
        number(text)
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| *n <= maximum)
            .ok_or(ParseErrorKind::InvalidLiteral)
    };
    let expected = parse(literal.strip_prefix('=').unwrap_or(literal))?;
    let mask = mask.map_or(Ok(maximum), parse)?;
    Ok((
        Predicate::Number {
            width,
            big_endian,
            mask,
            expected,
        },
        width,
    ))
}

fn token(line: &str) -> Option<(&str, &str)> {
    let line = line.trim_start();
    if line.is_empty() {
        return None;
    }
    let mut escaped = false;
    for (at, ch) in line.char_indices() {
        if ch.is_whitespace() && !(ch == ' ' && escaped) {
            return Some((&line[..at], line[at..].trim_start()));
        }
        escaped = ch == '\\' && !escaped;
    }
    Some((line, ""))
}

fn number(text: &str) -> Option<u64> {
    if let Some(hex) = text.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else if text.starts_with('0') && text.len() > 1 {
        u64::from_str_radix(&text[1..], 8).ok()
    } else if text.bytes().all(|b| b.is_ascii_digit()) {
        text.parse().ok()
    } else {
        None
    }
}

fn decode(text: &str) -> Result<Vec<u8>, ParseErrorKind> {
    let mut result = Vec::new();
    let mut input = text.bytes().peekable();
    while let Some(byte) = input.next() {
        let byte = if byte == b'\\' {
            match input.next().ok_or(ParseErrorKind::InvalidLiteral)? {
                b'x' => {
                    let hi = input
                        .next()
                        .and_then(hex)
                        .ok_or(ParseErrorKind::InvalidLiteral)?;
                    let lo = input
                        .next()
                        .and_then(hex)
                        .ok_or(ParseErrorKind::InvalidLiteral)?;
                    hi * 16 + lo
                }
                first @ b'0'..=b'7' => {
                    let mut n = u16::from(first - b'0');
                    for _ in 0..2 {
                        if let Some(next @ b'0'..=b'7') = input.peek().copied() {
                            input.next();
                            n = n * 8 + u16::from(next - b'0');
                        } else {
                            break;
                        }
                    }
                    u8::try_from(n).map_err(|_| ParseErrorKind::InvalidLiteral)?
                }
                b'n' => b'\n',
                b'r' => b'\r',
                b't' => b'\t',
                b'\\' => b'\\',
                b' ' => b' ',
                _ => return Err(ParseErrorKind::InvalidLiteral),
            }
        } else if byte.is_ascii() {
            byte
        } else {
            return Err(ParseErrorKind::InvalidLiteral);
        };
        if result.len() == MAX_PREFIX_BYTES {
            return Err(ParseErrorKind::PrefixLimit);
        }
        result.push(byte);
    }
    Ok(result)
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn compile_plan() -> Result<CompilePlan, CopyError> {
    let records = Layout::array::<Rule>(MAX_RULES)
        .map_err(|_| CopyError::SizeOverflow)?
        .size()
        .checked_add(
            Layout::array::<Check>(MAX_CHECKS)
                .map_err(|_| CopyError::SizeOverflow)?
                .size(),
        )
        .ok_or(CopyError::SizeOverflow)?;
    // The fixed count limits are powers of two. Four copies cover live/final
    // arrays, old/new amortized vector growth and literal/name replacement overlap.
    let peak_bytes = records
        .checked_add(MAX_RULE_TEXT_BYTES)
        .and_then(|n| n.checked_mul(4))
        .ok_or(CopyError::SizeOverflow)?;
    let peak_allocations = MAX_CHECKS
        .checked_mul(4)
        .and_then(|n| n.checked_add(MAX_RULES.checked_mul(8)?))
        .and_then(|n| n.checked_add(16))
        .ok_or(CopyError::SizeOverflow)?;
    Ok(CompilePlan {
        peak_bytes,
        peak_allocations,
    })
}
