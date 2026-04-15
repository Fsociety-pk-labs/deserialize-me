# DeserializeMe - CTF Challenge

## Challenge
YAML deserialization vulnerability (CVE-2024-YAML-DESER) in Node.js application.

## Objective
Exploit the vulnerability to retrieve the flag.

## Installation
```bash
npm install
npm start
# Visit http://localhost:3000
```

## Endpoints
- `GET /` - Main interface
- `GET /api/system-config?data=<YAML>` - Vulnerable endpoint
- `GET /admin/dashboard` - Admin panel

## Flag Format
`fsociety{...}`

## Difficulty
Medium
vercel deploy

# Or connect your GitHub repo to Vercel for auto-deployment
```

## Files
- `index.html` - Complete interactive training platform (Vercel-ready)

## The Final Flag
Only available after completing all 5 checkpoints successfully.

Format: `fsociety{...}`

---

## Real-World Context

This vulnerability mirrors actual security issues found in:
- Poorly designed web applications
- Template injection vulnerabilities
- Server-side template injection (SSTI)
- Dynamic code evaluation systems

## Defense Strategies
- Never use eval() with user input
- Use textContent instead of innerHTML for dynamic content
- Implement Content Security Policy (CSP)
- Validate and sanitize all user inputs
- Use templating engines safely
