# Velocities SI — static web edition

Built with HTML, CSS, and vanilla JavaScript. No Java runtime, Node dependencies, build step, database, or Docker is needed. This is a **browser-local demonstration**, not a deployed security monitoring service or the complete production platform in the supplied brief.

## Run

Open `index.html` directly, or serve this directory with any static web server. If Python is installed:

```sh
python -m http.server 8080
```

Visit http://localhost:8080. Browser storage can behave differently for `file:` URLs; an HTTP server is recommended. Google Fonts is optional; the UI falls back to system fonts offline.

## Host on Vercel

1. Upload the contents of this folder to a GitHub repository.
2. Import that repository into Vercel.
3. Choose framework preset **Other**, leave the build command empty, and set output directory to `.` (the repository root containing `index.html`).
4. Deploy. The included `vercel.json` adds response security headers.

Alternatively, upload the folder to Netlify Drop or enable GitHub Pages for the repository root. Those providers do not apply Vercel's custom headers. Hash-based navigation works without URL rewrite rules. No environment variables or secrets are needed. Hosting itself has not been performed.

## Included behavior

- Responsive dark SOC dashboard; activity chart and severity chart derived from local records.
- Searchable events, stage filter, raw JSON evidence viewer, JSON export.
- Two deterministic suspicious scenario sequences and a normal baseline. Start, pause, resume, and stop controls; one scenario at a time.
- Per-run incident correlation, linked event IDs, rule explanations, MITRE hypotheses, evolving weighted risk inputs.
- Investigation, true-positive resolution, false-positive classification.
- Simulated approval, rejection, 30-minute lazy expiry, isolation, and rollback. Execution checks approval again.
- Local decision history, workspace export, printable audit report, reset.
- Browser persistence using localStorage. No shared or externally ingested data.

## Demo

1. Click **Run scenario**; wait about five seconds.
2. Open Incident Center and investigate the credential-compromise incident.
3. Inspect Attack Chain, Threat Detection, and Risk Intelligence.
4. In Response Center, review evidence, approve the simulation, and simulate isolation. Roll it back if desired.
5. Resolve the incident and export Reports & Audit.
6. Start S2 from Demo Control to explore reconnaissance evidence.

## Scope and limitations

The original brief's Next.js foundation was replaced at the user's request with plain HTML/CSS/JavaScript. This delivers a hostable interactive front end; it does not satisfy production Phase 1 authentication/Drizzle requirements. Browser code cannot securely enforce RBAC or four-eyes approvals. The avatar is a demo label, not a signed-in identity. All users of a browser profile can edit local records, approvals, and audit history. Do not enter sensitive logs, credentials, or personal information.

No trained ML, measured accuracy, real-time ingestion, server authentication, backend authorization, PostgreSQL, immutable audit chain, or actual lab executor is included. Detection rules apply to controlled scenario sequences, not arbitrary log ingestion. Each run is correlated separately. Timestamps vary; sequence and risk calculation are deterministic. Simulation state is local and cannot change networks, accounts, or hosts. For shared production use, implement a backend, validate all input, enforce server-side roles and approvals, and persist records in a database.

The reset control removes this app's browser data after confirmation. Closing the tab stops the scenario timer. Existing data is retained locally, but an interrupted scenario cannot resume after reload. Storage limits and private browsing can prevent persistence.

## Files

`index.html` — accessible page shell and dialog.
`styles.css` — responsive styles and print layout.
`app.js` — navigation, synthetic scenarios, local state, views, and actions.
`vercel.json` — static-hosting security headers.
`TEST-REPORT.md` — verification results and limits.

Developed for Team Velocities · ABCS-03.
