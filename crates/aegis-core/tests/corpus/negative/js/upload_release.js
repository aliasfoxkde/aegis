// Negative corpus: executable-upload false-positive regression.
//
// Regression entry for the 2026-09-22 false-positive audit (commit
// e0abd61): the rule used to match a script extension anywhere on a
// line that also said upload, so release tooling that builds shell
// scripts and then uploads artifacts was flagged. The corrected rule
// requires an upload-style call feeding an executable extension;
// every line below fired under the old regex and must stay silent
// under the current one.

// aegis:expect-none executable-file-upload

// Build the POSIX installer, then publish the release tarball.
exec("./scripts/build.sh && release-tool upload dist/app.tar.gz");

// The upload stage of the pipeline runs after packaging.
const stages = ["lint", "test", "package", "upload"];

// Reference docs for the legacy sample pages.
const docPaths = ["docs/pipeline.md", "examples/legacy.php", "README.md"];
