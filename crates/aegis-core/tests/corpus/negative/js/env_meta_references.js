// Negative corpus: env-file-in-git false-positive regression.
//
// Regression entry for the 2026-09-23 Control Center pipeline-gate audit:
// the rule matched the dotfile token for environment files anywhere in a
// file, so frontend and Node code that reads environment VARIABLES through
// meta and process env objects was flagged as a committed env file. The
// corrected rule requires the dotfile token to start a path segment; every
// line below fired under the old regex and must stay silent under the
// current one.

// aegis:expect-none env-file-in-git

const apiUrl = import.meta.env.VITE_API_URL;

const mode = import.meta.env.MODE;

const homeDir = process.env.HOME;
