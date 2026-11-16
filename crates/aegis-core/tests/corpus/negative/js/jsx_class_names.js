// Negative corpus: PII-output-marker false-positive regression.
//
// Regression entry for issue #186: the rule matched a bare three-letter
// abbreviation anywhere on a line, so the camel-case rendering inside
// React's `className` attribute was reported as a high-severity PII
// marker on every JSX element in an application. The corrected rule
// requires the abbreviation to start at a word boundary (or after an
// underscore); every line below fired under the old regex and must stay
// silent under the current one.

// aegis:expect-none pii-output-marker

// The shell renders the workspace chrome around its children.
export function WorkspaceShell({ children }) {
  return (
    <section className="desktop-shell">
      <nav className="workspace-tabs">Tabs</nav>
      <button className="save-button" type="submit">
        Save
      </button>
    </section>
  );
}

// Class names are collected into a list before they are applied.
const classNames = ["desktop-shell", "workspace-tabs", "save-button"];

// The assignment below only reorders the collected names.
export const assignment = classNames.map((name) => name.trim());
