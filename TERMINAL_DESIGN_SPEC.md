# Terminal Design System Specification
**Reference Source:** [https://designprompts.dev/terminal](https://designprompts.dev/terminal)  
**Captured Analysis:** Full page scroll inspection from Header to Tree Directory Footer.

---

## 1. Design Identity & Principles

- **Surface & Ground:** Solid pitch black (`#000000`). No glassmorphism, no rounded cards, no simulated CRT curvature or blur glow around text.
- **Ink (Phosphor Green):** Primary `#66ff66` (`rgb(102, 255, 102)`), secondary/dim `#58ca58` (`rgb(88, 202, 88)`).
- **Edge / Hairlines:** Fine hairline green border `#255325` (`rgb(37, 83, 37)`).
- **Emphasis:** Pure white `#ffffff` reserved exclusively for display headers and high-contrast callouts.
- **Typography:** Strictly Monospaced — `IBM Plex Mono` / `TerminalPlex` with `tabular-nums`.
- **Character Spacing Units:** Measured in `ch` and character cell increments (`1ch`, `2ch`, `3ch`, `4ch`, `8ch`).
- **Control Corners:** `border-radius: 0` (strictly square).
- **Interaction Hover:** Complete color inversion (`background: #66ff66; color: #000000;`) on hover; visible 1px white outline on keyboard `:focus-visible`.
- **Cursor Motion:** Discrete block cursor (`█` or `▋`) blinking at `1.2s steps(1, end)` with disabled animation under `@media (prefers-reduced-motion: reduce)`.

---

## 2. Authoritative CSS Design Tokens

```css
:root {
  --dp-color-ground: #000000;
  --dp-color-ink: #66ff66;
  --dp-color-ink-muted: #58ca58;
  --dp-color-rule: #255325;
  --dp-color-emphasis: #ffffff;

  --dp-typography-face: "TerminalPlex", "IBM Plex Mono", monospace;
  --dp-typography-body: 18px;
  --dp-typography-label: 16px;
  --dp-typography-heading: 24px;
  --dp-typography-display: 40px;
  --dp-typography-display-narrow: 32px;

  --dp-typography-body-leading: 1.5;
  --dp-typography-display-leading: 1.2;
  --dp-typography-display-leading-narrow: 1.25;
  --dp-typography-list-leading: 27px;

  --dp-spacing-cell: 1ch;
  --dp-spacing-gutter: 2ch;
  --dp-spacing-column-gap: 3ch;
  --dp-spacing-column-gap-wide: 4ch;
  --dp-spacing-inset: 9px;
  --dp-spacing-row-compact: 18px;
  --dp-spacing-row: 27px;
  --dp-spacing-section-compact: 36px;
  --dp-spacing-section: 54px;

  --dp-radius-control: 0;
  --dp-border-hairline: 1px;
  --dp-motion-cursor: 1.2s;
}
```

---

## 3. Structural Anatomy & Section Layout

### 3.1 Session Header (`.session-header`)
- **Session Bar (`.session-bar`):** Full-width inverted green bar (`background: #66ff66; color: #000000;`):
  - Brand name (e.g. `Acme` / `SentinelAI`)
  - Subtitle path (e.g. `/ autonomous soc platform`)
  - Session status tag (e.g. `[ LIVE SESSION ]` / `[ DEMO SESSION ]`) pushed to the far right.
- **Sub-navigation (`nav`):**
  - Bracketed navigation items (`[Features]`, `[Simulation]`, `[Architecture]`, `[Pricing]`, `[FAQ]`).
  - Active path indicator (`~/sentinel` or `~/acme`) on the right.
  - Border-bottom: 1px solid `#255325`.

### 3.2 The Command & Output Grid
Every content section follows a 2-column structure:
```
+------------+-------------------------------------------------------+
| Gutter     | Command Text ($ prompt command --flags)               |
| [00]       |                                                       |
|            +-------------------------------------------------------+
|            | Output Content Block (Left border: 1px solid #255325) |
|            |                                                       |
+------------+-------------------------------------------------------+
```
- **Desktop Grid:** `grid-template-columns: 8ch minmax(0, 1fr)`.
- **Gutter Index:** `[00]`, `[01]`, `[02]`, etc. in `#58ca58`.
- **Left Rule:** 1px hairline border separating gutter from output.

### 3.3 Section Breakdown from the Reference Page

#### Section `[00]` - Hero & Startup
- Command: `$ acme --init` (or `$ sentinel --init --mode autonomous-defense`)
- Startup Banner: ASCII block typography wordmark + `[OK] session ready` indicator.
- Hero Layout:
  - Left column: Display headline (`h1` in `#ffffff`), description paragraphs, action links (`> Start free trial` inverted, `> Watch demo`).
  - Right column (`.stats`): Monospaced telemetry metrics separated by 1px green border (e.g. Active Endpoints, Ingestion SLA 99.99%, Mean Time to Contain < 500ms, Customer Savings).

#### Section `[01]` - About & Manifesto
- Command: `$ man acme` (or `$ man sentinel`)
- Heading: Upper-case summary statement.
- 2-Column explanatory prose detailing architecture and unified platform advantages.

#### Section `[02]` - Capabilities / Features Listing
- Command: `$ acme --list features`
- Structure: Numbered rows `01` to `06` in 3 columns:
  - `[Index: 3ch]` `[Title: 24ch UPPERCASE]` `[Description: 1fr]`
  - Separated by horizontal 1px hairline rules.

#### Section `[03]` - Technical Journal / Field Reports
- Command: `$ cat journal/*`
- Structure: 3-column article cards featuring:
  - Header tag: `[01]` and format `text/plain`.
  - Fixed-width ASCII art / tonal character renditions.
  - Date stamp, article title in uppercase, description, and author attribution (`by Sarah Chen`).

#### Section `[04]` - Workflow Execution (`--setup`)
- Command: `$ acme --setup`
- Step-by-step ordered list:
  - Inverted green numbers `[01]`, `[02]`, `[03]`.
  - Title & description of pipeline setup.

#### Section `[05]` - Results & Metrics (`--results`)
- Command: `$ acme --results`
- 2-column grid with `[+]` indicators for key value propositions.

#### Section `[06]` - Customer Testimonials (`team-feedback.log`)
- Command: `$ cat team-feedback.log`
- Quotes formatted with `>` indicator and author / role / company in fixed columns.

#### Section `[07]` - Pricing & Plan Matrix (`--select plan`)
- Command: `$ acme --select plan`
- Interactive comparison rows with:
  - Selection bracket `[ ]` vs `[x]`
  - Badge `* Most popular`
  - Price & 2-column feature bullet list with `+`
  - Inverted selection button `Select Plan ↵`

#### Section `[08]` - FAQ Disclosures (`--help`)
- Command: `$ acme --help`
- Native `<details>` & `<summary>` elements with sequential index (`01` - `07`) and dynamic toggle indicator `[+]` / `[-]`.

#### Section `[09]` - Closing Call To Action (`--start`)
- Command: `$ acme --start`
- Title, body, dual action buttons, and idle terminal prompt with blinking block cursor:
  `sentinel@demo:~$ █`

#### Section `[10]` - Footer Directory (`tree acme/`)
- Command: `$ tree acme/`
- 4-column directory tree using UNIX file-tree syntax (`├─ ` and `└─ `).
- Social links list + copyright note.

---

## 4. Dual-Pane Terminal & SOC Dashboard Integration
To maintain full fidelity with SentinelAI's interactive product demonstration while applying this exact design:
- Insert the synchronized motion-graphic terminal and dashboard simulation under an interactive command section (e.g. `[01] $ sentinel --stream live-telemetry`).
- The left terminal pane strictly uses the 8ch command gutter, timestamps, severity tags, and auto-scrolling log stream.
- The right SOC dashboard pane uses ASCII telemetry meters (`█` and `░`), MITRE matrices, multi-agent AI triage, and SOAR execution blocks.
