# Phishing Email Analyzer

A Python command-line tool that checks an email for common phishing red flags and gives it a risk score from 0 to 100.

No installs needed. It uses only the Python standard library.

## What it checks

**Sender checks**
- Display name pretending to be a brand (for example "PayPal" sent from a random domain)
- Reply-To address that differs from the sender
- Lookalike domains (`paypa1`, `micr0soft`, `paypal-secure`)

**Content checks**
- Urgent or threatening language
- Requests for passwords, bank details, or gift cards

**Link checks**
- Raw IP addresses, `@` tricks, URL shorteners
- Risky domain endings (`.xyz`, `.top`, `.zip`)
- Unencrypted `http` links, punycode, too many subdomains

**Attachment checks**
- Risky file types (`.exe`, `.zip`, `.docm`, `.html`)

## How to run

```bash
python phishing_analyzer.py --demo            # try the built-in sample emails
python phishing_analyzer.py email.txt         # analyze your own email
python phishing_analyzer.py email.txt --json  # JSON output
```

To test your own email, copy the full email text (with From, Subject, and body) into a file called `email.txt`.

## Example output

```
RISK SCORE: 100/100
VERDICT   : HIGH RISK - likely phishing
```

## How scoring works

Each type of red flag adds points (for example, a lookalike domain adds 25 and urgent language adds 10). Each type counts once, and the total is capped at 100.
- 60 or more: High risk
- 30 to 59: Medium risk
- Under 30: Low risk

## Limits

This is a rule-based learning project, not a replacement for professional email security tools. It can miss new tricks and can flag real emails by mistake.

## Ideas to extend it

- Check links against a free threat feed such as URLhaus
- Parse full email headers (SPF, DKIM, DMARC results)
- Add a small machine learning model trained on a phishing dataset
- Build a simple web page with Flask

## Skills shown

Python, regular expressions, email parsing, threat analysis, social engineering awareness, risk scoring.
