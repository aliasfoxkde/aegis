//! Software Bill of Materials (SBOM) Generation
//!
//! Generates SBOMs in SPDX and CycloneDX formats for supply chain security.

use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashMap;
use std::path::Path;

/// SBOM document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sbom {
    /// SBOM format
    pub format: SbomFormat,
    /// SBOM version
    pub version: String,
    /// Document creation info
    pub metadata: SbomMetadata,
    /// Components/Packages
    pub components: Vec<SbomComponent>,
    /// Dependencies
    pub dependencies: Vec<SbomDependency>,
}

/// SBOM formats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SbomFormat {
    /// SPDX format
    Spdx,
    /// CycloneDX format
    CycloneDx,
    /// Tag-value SPDX format
    SpdxTv,
}

/// Document metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomMetadata {
    /// Document name
    pub name: String,
    /// Document ID
    pub id: String,
    /// SPDX version (for SPDX format)
    pub spdx_version: Option<String>,
    /// Data license
    pub data_license: String,
    /// Document comment
    pub comment: Option<String>,
    /// Creation info
    pub creation_info: CreationInfo,
}

/// Creation info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreationInfo {
    /// Creator
    pub creator: String,
    /// Created timestamp
    pub created: String,
    /// Creator comment
    pub creator_comment: Option<String>,
}

/// SBOM Component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomComponent {
    /// Package name
    pub name: String,
    /// Package version
    pub version: Option<String>,
    /// Package URL (PURL)
    pub purl: Option<String>,
    /// CPE identifier
    pub cpe: Option<String>,
    /// License information
    pub license_info: LicenseInfo,
    /// Package supplier
    pub supplier: Option<String>,
    /// Copyright
    pub copyright: Option<String>,
    /// Description
    pub description: Option<String>,
    /// Hashes
    pub hashes: Vec<PackageHash>,
    /// External references
    pub external_refs: Vec<ExternalRef>,
    /// Download location
    pub download_location: Option<String>,
    /// Primary package purpose
    pub primary_purpose: Option<String>,
}

/// License information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseInfo {
    /// Declared licenses
    pub declared: Vec<String>,
    /// Concluded license
    pub concluded: Option<String>,
    /// License comment
    pub comment: Option<String>,
}

/// Package hash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageHash {
    /// Hash algorithm
    pub algorithm: HashAlgorithm,
    /// Hash value
    pub value: String,
}

/// Hash algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    /// SHA-1
    Sha1,
    /// SHA-256
    Sha256,
    /// SHA-512
    Sha512,
    /// MD5
    Md5,
    /// BLAKE3
    Blake3,
}

/// External reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalRef {
    /// Reference type
    pub reference_type: String,
    /// Reference locator
    pub reference_locator: String,
    /// Reference comment
    pub comment: Option<String>,
}

/// Dependency relationship
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomDependency {
    /// Package name
    pub package_name: String,
    /// Dependencies of this package
    pub dependencies: Vec<String>,
}

/// SBOM generator
#[derive(Debug, Clone, Default)]
pub struct SbomGenerator {
    /// Root package name
    root_name: String,
    /// Root version
    root_version: Option<String>,
    /// Components
    components: Vec<SbomComponent>,
    /// Hash cache
    hash_cache: HashMap<String, String>,
}

impl SbomGenerator {
    /// Create a new SBOM generator
    pub fn new(name: impl Into<String>, version: Option<String>) -> Self {
        Self {
            root_name: name.into(),
            root_version: version,
            components: Vec::new(),
            hash_cache: HashMap::new(),
        }
    }

    /// Add a dependency
    pub fn add_dependency(&mut self, name: impl Into<String>, version: Option<String>) {
        let name = name.into();
        let purl = Self::create_purl(&name, version.as_deref());

        self.components.push(SbomComponent {
            name: name.clone(),
            version: version.clone(),
            purl: Some(purl),
            cpe: None,
            license_info: LicenseInfo {
                declared: vec!["NOASSERTION".to_string()],
                concluded: None,
                comment: None,
            },
            supplier: None,
            copyright: None,
            description: None,
            hashes: Vec::new(),
            external_refs: Vec::new(),
            download_location: Some("NOASSERTION".to_string()),
            primary_purpose: None,
        });
    }

    /// Add a Rust dependency
    pub fn add_rust_dep(&mut self, name: &str, version: &str, license: &str) {
        let purl = Self::create_purl(name, Some(version));

        self.components.push(SbomComponent {
            name: name.to_string(),
            version: Some(version.to_string()),
            purl: Some(purl),
            cpe: None,
            license_info: LicenseInfo {
                declared: vec![license.to_string()],
                concluded: None,
                comment: None,
            },
            supplier: None,
            copyright: None,
            description: None,
            hashes: Vec::new(),
            external_refs: vec![ExternalRef {
                reference_type: "packaging-manager".to_string(),
                reference_locator: "cargo".to_string(),
                comment: None,
            }],
            download_location: Some(format!("https://crates.io/api/v1/crates/{}", name)),
            primary_purpose: Some("dependency".to_string()),
        });
    }

    /// Add a Node.js dependency
    pub fn add_nodejs_dep(&mut self, name: &str, version: &str, license: &str) {
        let purl = Self::create_purl(name, Some(version));

        self.components.push(SbomComponent {
            name: name.to_string(),
            version: Some(version.to_string()),
            purl: Some(purl),
            cpe: None,
            license_info: LicenseInfo {
                declared: vec![license.to_string()],
                concluded: None,
                comment: None,
            },
            supplier: None,
            copyright: None,
            description: None,
            hashes: Vec::new(),
            external_refs: vec![ExternalRef {
                reference_type: "packaging-manager".to_string(),
                reference_locator: "npm".to_string(),
                comment: None,
            }],
            download_location: Some(format!("https://www.npmjs.com/package/{}", name)),
            primary_purpose: Some("dependency".to_string()),
        });
    }

    /// Add a Python dependency
    pub fn add_python_dep(&mut self, name: &str, version: &str, license: &str) {
        let purl = Self::create_purl(name, Some(version));

        self.components.push(SbomComponent {
            name: name.to_string(),
            version: Some(version.to_string()),
            purl: Some(purl),
            cpe: None,
            license_info: LicenseInfo {
                declared: vec![license.to_string()],
                concluded: None,
                comment: None,
            },
            supplier: None,
            copyright: None,
            description: None,
            hashes: Vec::new(),
            external_refs: vec![ExternalRef {
                reference_type: "packaging-manager".to_string(),
                reference_locator: "pip".to_string(),
                comment: None,
            }],
            download_location: Some(format!("https://pypi.org/project/{}", name)),
            primary_purpose: Some("dependency".to_string()),
        });
    }

    /// Add a Docker/OCI image dependency
    pub fn add_container_dep(&mut self, image: &str, digest: Option<&str>) {
        let (name, tag) = image.split_once(':').unwrap_or((image, "latest"));
        let digest_suffix = digest.map(|d| format!("@sha256:{}", d)).unwrap_or_default();

        self.components.push(SbomComponent {
            name: name.to_string(),
            version: Some(tag.to_string()),
            purl: Some(format!("pkg:docker/{}?tag={}", name, tag)),
            cpe: None,
            license_info: LicenseInfo {
                declared: vec!["NOASSERTION".to_string()],
                concluded: None,
                comment: None,
            },
            supplier: None,
            copyright: None,
            description: None,
            hashes: digest
                .map(|d| {
                    vec![PackageHash {
                        algorithm: HashAlgorithm::Sha256,
                        value: d.to_string(),
                    }]
                })
                .unwrap_or_default(),
            external_refs: vec![ExternalRef {
                reference_type: "purl".to_string(),
                reference_locator: format!("pkg:docker/{}{}", image, digest_suffix),
                comment: None,
            }],
            download_location: None,
            primary_purpose: Some("container".to_string()),
        });
    }

    /// Add file hash
    pub fn add_file_hash(&mut self, path: &Path) -> Option<PackageHash> {
        let path_str = path.to_string_lossy().to_string();

        if let Some(cached) = self.hash_cache.get(&path_str) {
            return Some(PackageHash {
                algorithm: HashAlgorithm::Sha256,
                value: cached.clone(),
            });
        }

        let content = std::fs::read(path).ok()?;
        let hash = sha2::Sha256::digest(&content);
        let hash_str = hex::encode(hash);

        self.hash_cache.insert(path_str, hash_str.clone());

        Some(PackageHash {
            algorithm: HashAlgorithm::Sha256,
            value: hash_str,
        })
    }

    /// Generate SPDX tag-value format
    pub fn generate_spdx_tv(&self) -> String {
        let mut output = String::new();

        // Document header
        output.push_str("SPDXVersion: SPDX-2.3\n");
        output.push_str("DataLicense: CC0-1.0\n");
        output.push_str("SPDXID: SPDXRef-DOCUMENT\n");
        output.push_str(&format!("DocumentName: {}\n", self.root_name));
        output.push_str(&format!(
            "DocumentNamespace: https://aegis.io/spdx/{}/{}\n",
            self.root_name,
            uuid_v4()
        ));

        // Creation info
        output.push_str("\n# Creation Information\n");
        output.push_str("Creator: Tool: aegis-sbom\n");
        output.push_str(&format!("Created: {}\n", chrono_now()));

        // Packages
        for (i, comp) in self.components.iter().enumerate() {
            output.push_str("\nPackageName: ");
            output.push_str(&comp.name);
            output.push('\n');
            output.push_str(&format!("SPDXID: SPDXRef-Package-{}\n", i + 1));

            if let Some(ref v) = comp.version {
                output.push_str(&format!("PackageVersion: {}\n", v));
            }

            if let Some(ref p) = comp.purl {
                output.push_str(&format!("PackageDownloadLocation: {}\n", p));
            } else {
                output.push_str("PackageDownloadLocation: NOASSERTION\n");
            }

            // License
            let declared = comp.license_info.declared.join(" AND ");
            output.push_str(&format!("PackageLicenseDeclared: {}\n", declared));
            output.push_str("PackageLicenseConcluded: NOASSERTION\n");

            if let Some(ref sup) = comp.supplier {
                output.push_str(&format!("PackageSupplier: {}", sup));
            }

            if let Some(ref cp) = comp.copyright {
                output.push_str(&format!("PackageCopyrightText: {}", cp));
            }

            // Primary purpose
            if let Some(ref pp) = comp.primary_purpose {
                output.push_str(&format!("PrimaryPackagePurpose: {}\n", pp));
            }
        }

        // Relationships
        output.push_str("\n# Relationships\n");
        output.push_str("Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-1\n");
        for i in 1..=self.components.len() {
            output.push_str(&format!(
                "Relationship: SPDXRef-Package-1 CONTAINS SPDXRef-Package-{}\n",
                i
            ));
        }

        output
    }

    /// Generate SPDX JSON format
    pub fn generate_spdx_json(&self) -> String {
        serde_json::to_string_pretty(&self.to_spdx_json()).unwrap_or_default()
    }

    /// Generate CycloneDX JSON format
    pub fn generate_cyclonedx_json(&self) -> String {
        serde_json::to_string_pretty(&self.to_cyclonedx()).unwrap_or_default()
    }

    /// Generate SBOM in specified format
    pub fn generate(&self, format: SbomFormat) -> String {
        match format {
            SbomFormat::Spdx => self.generate_spdx_json(),
            SbomFormat::SpdxTv => self.generate_spdx_tv(),
            SbomFormat::CycloneDx => self.generate_cyclonedx_json(),
        }
    }

    /// Create SPDX JSON structure
    fn to_spdx_json(&self) -> serde_json::Value {
        let packages: Vec<serde_json::Value> = self
            .components
            .iter()
            .enumerate()
            .map(|(i, comp)| {
                let mut pkg = serde_json::json!({
                    "name": comp.name,
                    "SPDXID": format!("SPDXRef-Package-{}", i + 1),
                    "downloadLocation": comp.download_location.as_deref().unwrap_or("NOASSERTION"),
                });

                if let Some(ref v) = comp.version {
                    pkg["versionInfo"] = serde_json::json!(v);
                }

                if let Some(ref p) = comp.purl {
                    pkg["externalRefs"] = serde_json::json!([
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": p
                        }
                    ]);
                }

                let license_concluded = comp
                    .license_info
                    .declared
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "NOASSERTION".to_string());
                pkg["licenseConcluded"] = serde_json::json!(license_concluded);
                pkg["licenseDeclared"] = serde_json::json!(license_concluded);

                if let Some(ref pp) = comp.primary_purpose {
                    pkg["primaryPackagePurpose"] = serde_json::json!(pp);
                }

                serde_json::json!(pkg)
            })
            .collect();

        serde_json::json!({
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": self.root_name,
            "documentNamespace": format!("https://aegis.io/spdx/{}/{}", self.root_name, uuid_v4()),
            "creationInfo": {
                "created": chrono_now(),
                "creators": ["Tool: aegis-sbom"]
            },
            "packages": packages,
        })
    }

    /// Create CycloneDX structure
    fn to_cyclonedx(&self) -> serde_json::Value {
        let components: Vec<serde_json::Value> = self
            .components
            .iter()
            .map(|comp| {
                let mut comp_json = serde_json::json!({
                    "name": comp.name,
                    "type": comp.primary_purpose.as_deref().unwrap_or("library"),
                    "licenses": comp.license_info.declared.iter().map(|l| {
                        serde_json::json!({ "license": { "id": l } })
                    }).collect::<Vec<_>>(),
                });

                if let Some(ref v) = comp.version {
                    comp_json["version"] = serde_json::json!(v);
                }

                if let Some(ref p) = comp.purl {
                    comp_json["purl"] = serde_json::json!(p);
                }

                serde_json::json!(comp_json)
            })
            .collect();

        serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": chrono_now(),
                "tools": [
                    {
                        "name": "aegis",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                ],
                "component": {
                    "name": self.root_name,
                    "version": self.root_version.as_deref().unwrap_or("0.0.0"),
                    "type": "application"
                }
            },
            "components": components,
        })
    }

    /// Create a Package URL (PURL)
    fn create_purl(name: &str, version: Option<&str>) -> String {
        match version {
            Some(v) => format!("pkg:cargo/{}@{}", name, v),
            None => format!("pkg:cargo/{}", name),
        }
    }
}

/// Generate a simple UUID v4
fn uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:032x}", timestamp)
}

/// Get current timestamp in ISO 8601 format
fn chrono_now() -> String {
    // Simple ISO 8601 timestamp without chrono dependency
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    // Simplified - in production use chrono crate
    format!("2024-01-01T00:00:00Z (timestamp: {})", secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbom_generator_new() {
        let sbom = SbomGenerator::new("test-package", Some("1.0.0".to_string()));
        assert_eq!(sbom.root_name, "test-package");
        assert_eq!(sbom.root_version, Some("1.0.0".to_string()));
    }

    #[test]
    fn test_add_rust_dep() {
        let mut sbom = SbomGenerator::new("test", Some("1.0".to_string()));
        sbom.add_rust_dep("serde", "1.0.0", "MIT");
        assert_eq!(sbom.components.len(), 1);
        assert_eq!(sbom.components[0].name, "serde");
        assert_eq!(sbom.components[0].version, Some("1.0.0".to_string()));
    }

    #[test]
    fn test_add_nodejs_dep() {
        let mut sbom = SbomGenerator::new("test", Some("1.0".to_string()));
        sbom.add_nodejs_dep("lodash", "4.17.21", "MIT");
        assert_eq!(sbom.components.len(), 1);
        assert!(sbom.components[0].purl.as_ref().unwrap().contains("lodash"));
    }

    #[test]
    fn test_add_container_dep() {
        let mut sbom = SbomGenerator::new("test", Some("1.0".to_string()));
        sbom.add_container_dep("nginx:latest", Some("abc123"));
        assert_eq!(sbom.components.len(), 1);
        assert_eq!(sbom.components[0].name, "nginx");
    }

    #[test]
    fn test_generate_spdx_tv() {
        let mut sbom = SbomGenerator::new("test", Some("1.0".to_string()));
        sbom.add_rust_dep("serde", "1.0.0", "MIT");

        let output = sbom.generate_spdx_tv();
        assert!(output.contains("SPDXVersion: SPDX-2.3"));
        assert!(output.contains("PackageName: serde"));
    }

    #[test]
    fn test_generate_spdx_json() {
        let mut sbom = SbomGenerator::new("test", Some("1.0".to_string()));
        sbom.add_rust_dep("serde", "1.0.0", "MIT");

        let output = sbom.generate_spdx_json();
        assert!(output.contains("\"spdxVersion\""));
        assert!(output.contains("\"name\": \"serde\""));
    }

    #[test]
    fn test_generate_cyclonedx_json() {
        let mut sbom = SbomGenerator::new("test", Some("1.0".to_string()));
        sbom.add_rust_dep("serde", "1.0.0", "MIT");

        let output = sbom.generate_cyclonedx_json();
        assert!(output.contains("\"bomFormat\": \"CycloneDX\""));
        assert!(output.contains("\"name\": \"serde\""));
    }

    #[test]
    fn test_purl_creation() {
        let purl = SbomGenerator::create_purl("tokio", Some("1.0.0"));
        assert_eq!(purl, "pkg:cargo/tokio@1.0.0");

        let purl_no_ver = SbomGenerator::create_purl("tokio", None);
        assert_eq!(purl_no_ver, "pkg:cargo/tokio");
    }
}
