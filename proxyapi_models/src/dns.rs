//! DNS names retain label boundaries and arbitrary octets (RFC 1035 and RFC 4343).

use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

/// An absolute DNS name, preserving the client's label bytes and case.
///
/// Equality, hashing, and subdomain checks ignore ASCII case only. Display and
/// serialization use DNS presentation syntax: dots within labels and backslashes
/// are escaped, and non-printable or non-ASCII octets use decimal `\DDD` escapes.
/// The final root dot is omitted except for the root name itself (`.`).
///
/// ```
/// use proxyapi_models::DnsName;
///
/// let domain: DnsName = "example.org".parse()?;
/// let child: DnsName = "www.Example.org.".parse()?;
/// assert!(child.is_subdomain_of(&domain));
/// # Ok::<(), proxyapi_models::DnsNameError>(())
/// ```
#[derive(Clone, Debug, Eq)]
pub struct DnsName {
    labels: Vec<Vec<u8>>,
}

/// An invalid DNS name or presentation escape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsNameError {
    /// Only the implicit terminating root label may be empty.
    EmptyLabel,
    /// A label exceeds the DNS limit of 63 octets.
    LabelTooLong,
    /// The uncompressed name, including lengths and root, exceeds 255 octets.
    NameTooLong,
    /// An escape is incomplete, non-decimal, or outside the byte range.
    InvalidEscape,
}

impl fmt::Display for DnsNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EmptyLabel => "DNS name contains an empty label",
            Self::LabelTooLong => "DNS label exceeds 63 octets",
            Self::NameTooLong => "DNS name exceeds 255 wire octets",
            Self::InvalidEscape => {
                "invalid DNS escape: expected a character or three decimal digits in 000..255"
            }
        })
    }
}

impl std::error::Error for DnsNameError {}

impl DnsName {
    /// Construct a name from non-empty labels. An empty iterator denotes root;
    /// the terminating empty root label must not be included.
    pub fn from_labels<I, L>(labels: I) -> Result<Self, DnsNameError>
    where
        I: IntoIterator<Item = L>,
        L: AsRef<[u8]>,
    {
        let mut name = Self { labels: Vec::new() };
        let mut wire_len = 1; // Terminating root label.
        for label in labels {
            let label = label.as_ref();
            if label.is_empty() {
                return Err(DnsNameError::EmptyLabel);
            }
            if label.len() > 63 {
                return Err(DnsNameError::LabelTooLong);
            }
            wire_len += 1 + label.len();
            if wire_len > 255 {
                return Err(DnsNameError::NameTooLong);
            }
            name.labels.push(label.to_vec());
        }
        Ok(name)
    }

    /// Original labels, from the leftmost label toward the root (not included).
    pub fn labels(&self) -> &[Vec<u8>] {
        &self.labels
    }

    /// Whether this name equals `parent` or is below it, comparing whole labels.
    /// Every name is a subdomain of the root name.
    pub fn is_subdomain_of(&self, parent: &Self) -> bool {
        self.labels.len() >= parent.labels.len()
            && self
                .labels
                .iter()
                .rev()
                .zip(parent.labels.iter().rev())
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
    }
}

impl PartialEq for DnsName {
    fn eq(&self, other: &Self) -> bool {
        self.labels.len() == other.labels.len()
            && self
                .labels
                .iter()
                .zip(&other.labels)
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
    }
}

impl Hash for DnsName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.labels.len().hash(state);
        for label in &self.labels {
            label.len().hash(state);
            for byte in label {
                byte.to_ascii_lowercase().hash(state);
            }
        }
    }
}

impl fmt::Display for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.labels.is_empty() {
            return f.write_str(".");
        }
        for (index, label) in self.labels.iter().enumerate() {
            if index != 0 {
                f.write_str(".")?;
            }
            for &byte in label {
                match byte {
                    b'.' | b'\\' => write!(f, "\\{}", char::from(byte))?,
                    b'!'..=b'~' => write!(f, "{}", char::from(byte))?,
                    _ => write!(f, "\\{byte:03}")?,
                }
            }
        }
        Ok(())
    }
}

impl FromStr for DnsName {
    type Err = DnsNameError;

    /// Parse DNS presentation syntax, with an optional final root dot.
    /// Empty text also denotes root for compatibility with older captures.
    /// Unescaped UTF-8 is retained as bytes; no IDNA conversion is performed.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.is_empty() || text == "." {
            return Self::from_labels(std::iter::empty::<&[u8]>());
        }
        let bytes = text.as_bytes();
        let mut labels = Vec::new();
        let mut label = Vec::new();
        let mut cursor = 0;
        let mut wire_len = 1;
        while let Some(&byte) = bytes.get(cursor) {
            cursor += 1;
            if byte == b'.' {
                if label.is_empty() {
                    return Err(DnsNameError::EmptyLabel);
                }
                labels.push(std::mem::take(&mut label));
                continue;
            }
            let byte = if byte == b'\\' {
                let &escaped = bytes.get(cursor).ok_or(DnsNameError::InvalidEscape)?;
                if escaped.is_ascii_digit() {
                    let digits = bytes
                        .get(cursor..cursor + 3)
                        .filter(|digits| digits.iter().all(u8::is_ascii_digit))
                        .ok_or(DnsNameError::InvalidEscape)?;
                    let value = u16::from(digits[0] - b'0') * 100
                        + u16::from(digits[1] - b'0') * 10
                        + u16::from(digits[2] - b'0');
                    cursor += 3;
                    u8::try_from(value).map_err(|_| DnsNameError::InvalidEscape)?
                } else {
                    cursor += 1;
                    escaped
                }
            } else {
                byte
            };
            if label.is_empty() {
                wire_len += 1; // Label length octet.
            }
            wire_len += 1;
            if wire_len > 255 {
                return Err(DnsNameError::NameTooLong);
            }
            label.push(byte);
            if label.len() > 63 {
                return Err(DnsNameError::LabelTooLong);
            }
        }
        if !label.is_empty() {
            labels.push(label);
        }
        // Labels and wire length were checked while parsing.
        Ok(Self { labels })
    }
}

impl Serialize for DnsName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for DnsName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}
