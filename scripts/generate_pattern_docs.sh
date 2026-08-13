#!/bin/bash
# Generate pattern documentation from Rust source files

CATEGORIES=(
    "secrets:Secrets & Credentials:40"
    "pii:PII & Privacy:39"
    "security_hardening:Security Hardening:33"
    "web_security:Web Security:37"
    "supply_chain:Supply Chain:35"
    "infrastructure:Infrastructure as Code:55"
    "cloud_native:Cloud Native:38"
    "code_quality:Code Quality:15"
    "performance:Performance:22"
    "accessibility:Accessibility:22"
    "frameworks:Frameworks:31"
    "compliance:Compliance:33"
    "devops:DevOps & CI/CD:15"
)

OUTPUT_DIR="docs/patterns/categories"
mkdir -p "$OUTPUT_DIR"

for entry in "${CATEGORIES[@]}"; do
    IFS=':' read -r file name count <<< "$entry"
    src_file="crates/aegis-patterns/src/${file}.rs"

    if [ ! -f "$src_file" ]; then
        echo "Skipping $file - not found"
        continue
    fi

    echo "Generating $OUTPUT_DIR/${file}.md..."

    # Extract pattern lines and parse them
    grep -E '^\s+(name|severity|description):\s*"' "$src_file" | \
    sed 's/.*name:\s*"\([^"]*\)".*/NAME:\1/' | \
    sed 's/.*severity:\s*"\([^"]*\)".*/SEV:\1/' | \
    sed 's/.*description:\s*"\([^"]*\)".*/DESC:\1/' > "$OUTPUT_DIR/${file}.tmp"

    # Generate markdown
    cat > "$OUTPUT_DIR/${file}.md" << EOF
# ${name} (${count} patterns)

## Patterns

| Pattern | Severity | Description |
|---------|----------|-------------|
EOF

    # Process in groups of 3
    paste -d'|' \
        <(grep '^NAME:' "$OUTPUT_DIR/${file}.tmp" | sed 's/^NAME://') \
        <(grep '^SEV:' "$OUTPUT_DIR/${file}.tmp" | sed 's/^SEV://') \
        <(grep '^DESC:' "$OUTPUT_DIR/${file}.tmp" | sed 's/^DESC://') | \
    sed 's/^/| /' | sed 's/$/ |/' >> "$OUTPUT_DIR/${file}.md"

    rm "$OUTPUT_DIR/${file}.tmp"

    echo "" >> "$OUTPUT_DIR/${file}.md"
    echo "## Related" >> "$OUTPUT_DIR/${file}.md"
    echo "- [All Patterns](../README.md)" >> "$OUTPUT_DIR/${file}.md"
done

echo "Done!"
