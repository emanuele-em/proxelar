use std::collections::{HashMap, HashSet};

use proptest::prelude::*;
use proxyapi_models::{DnsName, DnsNameError};

#[test]
fn presentation_preserves_bytes_and_uses_decimal_escapes() {
    let name = DnsName::from_labels([b"A.B\\C\0 \x7f\xff".as_slice(), b"Example"]).unwrap();
    let text = r"A\.B\\C\000\032\127\255.Example";
    assert_eq!(name.to_string(), text);
    assert_eq!(text.parse::<DnsName>().unwrap().labels(), name.labels());
    assert_eq!(
        r"a\046b.example".parse::<DnsName>().unwrap().labels()[0],
        b"a.b"
    );
    assert_eq!(
        r"\065\066\067\255".parse::<DnsName>().unwrap().labels()[0],
        b"ABC\xff"
    );
    assert_eq!(r"\0324".parse::<DnsName>().unwrap().labels()[0], b" 4");
    assert_eq!(
        "é.test".parse::<DnsName>().unwrap().labels()[0],
        "é".as_bytes()
    );
}

#[test]
fn root_and_final_dot_have_one_representation() {
    let root: DnsName = ".".parse().unwrap();
    assert!(root.labels().is_empty());
    assert_eq!(root.to_string(), ".");
    assert_eq!("".parse::<DnsName>().unwrap(), root); // Legacy root captures.
    let name: DnsName = "Example.COM.".parse().unwrap();
    assert_eq!(name, "example.com".parse::<DnsName>().unwrap());
    assert_eq!(name.to_string(), "Example.COM");
    assert!(name.is_subdomain_of(&root));
    assert!(!root.is_subdomain_of(&name));
    assert!(root.is_subdomain_of(&root));
}

#[test]
fn equality_and_hashing_fold_ascii_case_and_preserve_boundaries() {
    let mut names = HashMap::new();
    names.insert("ExAmPlE.COM.".parse::<DnsName>().unwrap(), 42);
    assert_eq!(
        names.get(&"example.com".parse::<DnsName>().unwrap()),
        Some(&42)
    );
    let names: HashSet<_> = [
        DnsName::from_labels([b"a.b".as_slice(), b"c"]).unwrap(),
        "a.b.c".parse().unwrap(),
        "ab.c".parse().unwrap(),
        "a.bc".parse().unwrap(),
        DnsName::from_labels([b"\xdd".as_slice()]).unwrap(),
        DnsName::from_labels([b"\xfd".as_slice()]).unwrap(),
    ]
    .into_iter()
    .collect();
    assert_eq!(names.len(), 6);
}

#[test]
fn subdomains_are_matched_by_whole_labels() {
    let parent: DnsName = "example.org".parse().unwrap();
    for text in ["EXAMPLE.ORG.", "www.example.org", r"a\.b.example.org"] {
        assert!(text.parse::<DnsName>().unwrap().is_subdomain_of(&parent));
    }
    for text in [
        "badexample.org",
        "example.org.evil",
        r"evil\.example.org",
        r"example\.org",
    ] {
        assert!(
            !text.parse::<DnsName>().unwrap().is_subdomain_of(&parent),
            "{text}"
        );
    }
}

#[test]
fn invalid_labels_and_escapes_are_rejected() {
    for text in [".example", "example..org", "example.."] {
        assert_eq!(
            text.parse::<DnsName>().unwrap_err(),
            DnsNameError::EmptyLabel
        );
    }
    for text in [r"bad\", r"\1", r"\12", r"\12x", r"\256", r"\999"] {
        assert_eq!(
            text.parse::<DnsName>().unwrap_err(),
            DnsNameError::InvalidEscape
        );
        assert!(serde_json::from_value::<DnsName>(serde_json::json!(text)).is_err());
    }
    assert_eq!(
        DnsName::from_labels([b"".as_slice()]).unwrap_err(),
        DnsNameError::EmptyLabel
    );
    assert_eq!(
        DnsName::from_labels([vec![b'a'; 64]]).unwrap_err(),
        DnsNameError::LabelTooLong
    );
    assert_eq!(
        "a".repeat(64).parse::<DnsName>().unwrap_err(),
        DnsNameError::LabelTooLong
    );
}

#[test]
fn length_limits_apply_to_decoded_wire_octets() {
    let labels = [
        vec![b'a'; 63],
        vec![b'b'; 63],
        vec![b'c'; 63],
        vec![b'd'; 61],
    ];
    let name = DnsName::from_labels(&labels).unwrap();
    assert_eq!(name.to_string().parse::<DnsName>().unwrap(), name);
    let escaped = [
        r"\255".repeat(63),
        r"\255".repeat(63),
        r"\255".repeat(63),
        r"\255".repeat(61),
    ]
    .join(".");
    assert!(escaped.parse::<DnsName>().is_ok());
    let mut too_long = labels;
    too_long[3].push(b'd');
    assert_eq!(
        DnsName::from_labels(&too_long).unwrap_err(),
        DnsNameError::NameTooLong
    );
    assert_eq!(
        format!("{}d", name).parse::<DnsName>().unwrap_err(),
        DnsNameError::NameTooLong
    );
}

#[test]
fn serde_keeps_the_string_shape_and_accepts_existing_domain_strings() {
    let name: DnsName = serde_json::from_str(r#""Api.Example.test""#).unwrap();
    assert_eq!(
        serde_json::to_string(&name).unwrap(),
        r#""Api.Example.test""#
    );
    assert_eq!(
        serde_json::from_str::<DnsName>(r#""""#)
            .unwrap()
            .to_string(),
        "."
    );
}

proptest! {
    #[test]
    fn arbitrary_label_bytes_roundtrip_without_loss(
        labels in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..40), 0..6)
    ) {
        let name = DnsName::from_labels(&labels).unwrap();
        let parsed: DnsName = name.to_string().parse().unwrap();
        prop_assert_eq!(parsed.labels(), &labels);
        let decoded: DnsName = serde_json::from_str(&serde_json::to_string(&name).unwrap()).unwrap();
        prop_assert_eq!(decoded.labels(), &labels);
        let folded = DnsName::from_labels(labels.iter().map(|label| label.to_ascii_lowercase())).unwrap();
        let mut names = HashSet::new();
        names.insert(name);
        prop_assert!(names.contains(&folded));
    }
}
