# PII & Privacy (39 patterns)

## Patterns

| Pattern | Severity | Description |
|---------|----------|-------------|
| ssn|high|Social Security Number (SSN) detected |
| ssn-no-dashes|high|Possible SSN without dashes detected |
| itin|high|Individual Taxpayer Identification Number (ITIN) detected |
| ein|medium|Employer Identification Number (EIN) detected |
| email-address|low|Email address detected |
| phone-number|low|Phone number detected |
| international-phone|low|International phone number detected |
| credit-card-visa|critical|Visa credit card number detected |
| credit-card-mastercard|critical|Mastercard credit card number detected |
| credit-card-amex|critical|American Express credit card number detected |
| credit-card-discover|critical|Discover credit card number detected |
| credit-card-number-generic|critical|Generic credit card number detected |
| cvv|critical|Card verification value (CVV/CVC) detected |
| bank-routing-number|high|Bank routing number (ABA) detected |
| iban|high|International Bank Account Number (IBAN) detected |
| bitcoin-address|medium|Bitcoin address detected |
| aws-access-key|critical|AWS Access Key ID detected |
| full-name|low|Full name field detected |
| date-of-birth|medium|Date of birth field detected |
| passport-number|high|Passport number detected |
| drivers-license|high|Driver's license number detected |
| national-id|high|National ID number detected |
| military-id|high|Military ID detected |
| street-address|medium|Street address detected |
| zip-code|low|US ZIP code detected |
| uk-national-insurance|high|UK National Insurance number detected |
| canadian-sin|high|Canadian Social Insurance Number (SIN) detected |
| australian-tfn|high|Australian Tax File Number (TFN) detected |
| indian-aadhaar|high|Indian Aadhaar number detected |
| medical-record-number|high|Medical Record Number (MRN) detected |
| health-insurance-number|high|Health insurance number detected |
| prescription-number|medium|Prescription number detected |
| username-field|low|Username field with value detected |
| password-field|high|Password field with value detected |
| api-key-field|high|API key field with value detected |
| gdpr-personal-data|low|Reference to personal data detected |
| data-processing|low|Data processing agreement reference detected |
| consent-record|low|User consent record detected |
| right-to-erasure|low|Right to erasure request detected |

## Related
- [All Patterns](../README.md)
