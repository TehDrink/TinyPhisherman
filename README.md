# TinyPhisherman

TinyPhisherman is a backend-first phishing investigation app for the TinyFish hackathon. It supports:
- Active verification of suspicious URLs with TinyFish web automation
- Proactive typosquat hunting with `dnstwist` fallback logic
- Passive domain intelligence for DNS, TLS, RDAP, and redirects
- Threat scoring from OpenAI structured analysis with heuristic fallback

## Environment

Create `.env.local` with:

```bash
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4.1-mini
TINYFISH_API_KEY=
TINYFISH_API_URL=https://agent.tinyfish.ai
DNSTWIST_PATH=dnstwist
HUNT_MAX_CANDIDATES=12
HUNT_MAX_VARIANTS=5
```

Notes:
- If `OPENAI_API_KEY` is missing, the app falls back to heuristic phishing scoring.
- If `dnstwist` is unavailable, typosquat discovery falls back to the local generator.

## Run

```bash
npm run dev
```

## Build

```bash
npm run build
```

The build script uses webpack instead of Turbopack because Turbopack was unstable in this environment when processing CSS.

## API Routes

- `POST /api/scan`
  - body: `{ "url": "https://example.com" }`
- `POST /api/hunt`
  - body: `{ "domain": "example.com" }`

Both routes preserve the current summary fields used by the frontend and add richer evidence fields for later UI work.
