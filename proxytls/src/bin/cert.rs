#![allow(clippy::complexity, clippy::style, clippy::pedantic)]

use rcgen::{Certificate, CertificateParams,
	DistinguishedName, DnType, SanType,
	date_time_ymd};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let mut params :CertificateParams = Default::default();
	params.not_before = date_time_ymd(1975, 01, 01);
	params.not_after = date_time_ymd(4096, 01, 01);
	params.distinguished_name = DistinguishedName::new();
	params.distinguished_name.push(DnType::OrganizationName, "Crab widgits SE");
	params.distinguished_name.push(DnType::CommonName, "Master Cert");
	params.subject_alt_names = vec![SanType::DnsName("crabs.crabs".to_string()),
		SanType::DnsName("localhost".to_string())];

	let cert = Certificate::from_params(params)?;

	let pem_serialized = cert.serialize_pem()?;
	let der_serialized = pem::parse(&pem_serialized).unwrap().contents;
	println!("{pem_serialized}");
	println!("{}", cert.serialize_private_key_pem());
	std::fs::create_dir_all("certs/")?;
	fs::write("certs/cert.pem", &pem_serialized.as_bytes())?;
	fs::write("certs/cert.der", &der_serialized)?;
	fs::write("certs/key.pem", &cert.serialize_private_key_pem().as_bytes())?;
	fs::write("certs/key.der", &cert.serialize_private_key_der())?;
	Ok(())
}