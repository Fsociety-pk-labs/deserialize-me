# DeserializeMe - CTF Challenge

## Challenge Description
YAML deserialization vulnerability in Node.js application. The application accepts user-supplied YAML data and deserializes it without proper validation. Exploit this vulnerability to gain access to restricted information.

## Objective
Exploit the YAML deserialization vulnerability to access the admin dashboard and retrieve the flag.

## Challenge Difficulty
⭐⭐ **Medium** (45-60 minutes)

## Installation
```bash
npm install
npm start
```

Visit: `http://localhost:3000`

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main interface |
| `/api/system-config` | GET | YAML parser (vulnerable) |
| `/admin/dashboard` | GET | Admin panel |

## How to Solve
1. Analyze the `/api/system-config` endpoint behavior
2. Test YAML injection techniques
3. Exploit deserialization to bypass authentication
4. Access admin dashboard
5. Retrieve the flag

## Flag Format
`fsociety{...}`

## Hints
- Focus on YAML syntax and object deserialization
- Try different YAML payloads at the endpoint
- The admin panel contains the flag

## Requirements
- Node.js 16+
- npm packages (see package.json)

## Challenge Type
Web Security - Deserialization Attack
