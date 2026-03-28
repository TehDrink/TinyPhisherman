# TinyPhisherman

TinyPhisherman is a phishing investigation and brand-protection app built for the TinyFish hackathon. It combines active browser automation, passive domain intelligence, and LLM-based threat scoring into two workflows:

- **Check suspicious link** — Submit a URL for active TinyFish verification, passive DNS/TLS/RDAP checks, and a scored threat verdict.
- **Hunt phishing infrastructure** — Given a legitimate domain, discover typosquats and lookalike domains via Certificate Transparency logs (crt.sh), CIRCL, and dnstwist; rank them by risk; and deploy TinyFish against the most suspicious live variants.

## Architecture

```
src/
  app/
    api/
      scan/         POST /api/scan — single URL verification
      hunt/         POST /api/hunt — brand hunt (SSE streaming)
  lib/
    tinyfish.ts     TinyFish web agent client
    llm.ts          OpenAI-based DOM analysis + visual similarity
    passive-checks.ts  DNS, TLS, RDAP, redirect tracing
    typosquat.ts    Candidate discovery (crt.sh + CIRCL + dnstwist)
    certstream.ts   Certificate Transparency log lookup via crt.sh
    urlscan.ts      URLscan.io triage + submission
    threat-level.ts Threat level calculation
  prompts/
    tinyfish.ts     TinyFish goal prompt
    analysis.ts     LLM system + user prompts
  types/index.ts    Shared types
```

### Hunt pipeline stages (streamed via SSE)

| Stage | Progress | What happens |
|---|---|---|
| Discovery | 5–18% | crt.sh CT logs + CIRCL + dnstwist run in parallel |
| Baseline | 18–22% | TinyFish captures a screenshot of the original domain |
| Passive triage | 22–38% | DNS, TLS, RDAP, URLscan for up to 20 candidates |
| TinyFish visits | 38–76% | Top 8 suspicious live variants are actively scanned |
| LLM analysis | 76–95% | DOM analysis + visual similarity scoring per variant |

## Environment

Create `.env.local` from `.env.example`:

```bash
cp .env.example .env.local
```

| Variable | Required | Description |
|---|---|---|
| `TINYFISH_API_KEY` | Yes | TinyFish API key |
| `TINYFISH_API_URL` | Yes | TinyFish base URL (default: `https://agent.tinyfish.ai`) |
| `OPENAI_API_KEY` | No | If absent, falls back to heuristic scoring |
| `OPENAI_MODEL` | No | Default: `gpt-4.1-mini` |
| `URLSCAN_API_KEY` | No | Required for URLscan triage in the hunt pipeline |
| `DNSTWIST_PATH` | No | Path to `dnstwist` binary (default: `dnstwist`) |
| `HUNT_MAX_CANDIDATES` | No | Passive triage pool size (default: `20`) |
| `HUNT_MAX_VARIANTS` | No | Max variants sent to TinyFish (default: `8`) |

Notes:
- Without `OPENAI_API_KEY`, phishing scoring uses the heuristic analyser in `src/lib/llm.ts`.
- Without `dnstwist`, candidate discovery uses crt.sh + CIRCL only (no local installation needed for basic functionality).
- `URLSCAN_LOOKBACK_DAYS` controls how stale a cached URLscan result can be before it is ignored (default: `7`).

## Run

```bash
npm run dev
```

## Build

```bash
npm run build
```

The build script uses webpack instead of Turbopack because Turbopack was unstable in this environment when processing CSS.

## API

### `POST /api/scan`

Verify a single suspicious URL.

```json
{ "url": "https://suspicious-page.com", "useTinyfish": true }
```

Returns `ApiResponse<ScanResult>` with threat level, manipulation score, passive checks, screenshot, and evidence snippets.

### `POST /api/hunt`

Hunt for phishing infrastructure targeting a legitimate domain. Returns a **Server-Sent Events stream** — not a single JSON response.

```json
{ "domain": "google.com" }
```

Event format:

```
data: {"type":"progress","pct":15,"stage":"discovery","message":"Found 47 candidates via crt.sh+circl+dnstwist."}

data: {"type":"result","data":{...HuntResult}}

data: {"type":"error","error":"..."}
```

## Testing with known malicious URLs

> **Caution:** The URLs below are confirmed or suspected malicious. Do not visit them in a personal browser. Use TinyPhisherman's sandboxed TinyFish environment only.
>
> PhishTank and URLhaus were monitored but access was restricted by security challenges during collection.

### OpenPhish (Public Feed)

Use these with **Check suspicious link**:

```
https://teieperformance.com/app/QBP6cbknunXu5k3Fo8JFzW
http://s.teamwi.world/p/fwk-bzz/eqwjnihf
http://home-xinqiusports.com/khoviicf
https://teieperformance.com/app/rL7SKEuNuvXnUnznULS3BV
https://teieperformance.com/app/NxFbpZ4ewwjALMwQQXm7UD
https://tranquil-embeds-014754.framer.app/
https://teieperformance.com/app/Ga6otwpEh7EheynnkCK8S6
http://youthingstrategies.com/api
https://teieperformance.com/app/QM3ei6Ry7s7P7ugpY9antV
https://teieperformance.com/app/aLmhmcBFDwrBy9fh8KTDNR
```

### ANY.RUN (Public Submissions)

```
https://teslarecruitments.com
http://enformsakvakum.com
https://seguridadalfasbeneficiarios.com/bpjs1iqblk63
https://seguridadalfasbeneficiarios.com/1u2clzlmml8y
https://polizacancelacionalfa.com.co
https://puntostplus.com/index.php
```

### Hybrid Analysis (Recent Sandbox Submissions)

```
https://challenge440.raiselysite.com/bg-sub/posts/beast
https://challenge440.raiselysite.com/bg-sub/posts/fantasy-life
https://challenge440.raiselysite.com/bg-sub/posts/a-great-awakening
https://challenge440.raiselysite.com/bg-sub/posts/faces-of-death
https://gearboxz.com/
https://verney-carron.sk/re/config
```

For **Hunt phishing infrastructure**, try well-known brand domains that attract typosquat campaigns:

```
dbs.com.sg
paypal.com
google.com
apple.com
coinbase.com
```
