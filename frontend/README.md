# Sentinel X UI

Sentinel X UI is the React + TypeScript frontend for Backend API 1.0.

## Local development

Run the backend from the repository root:

```bash
python -m app.web
```

Then in a second terminal:

```bash
cd frontend
npm install
npm run build
npm run dev
```

Open `http://127.0.0.1:5173`.

The frontend defaults to `http://127.0.0.1:8765` for Backend API 1.0. Override this when needed:

```bash
VITE_API_URL=https://sentinel-api.example npm run dev
```

The backend accepts local UI origins from `SENTINEL_UI_ORIGINS`. The default is limited to the local Vite origins. Production deployments should set this explicitly.

## Design system

The primary interface is dark-first and optimized for dense cyber operations. Cyan represents operational state, violet represents AI/agent activity, amber represents uncertainty/elevated risk, red is reserved for critical state, and green represents verified/healthy state.

The UI is intentionally evidence-oriented: cinematic visual effects are decorative and must never replace real API state, provenance, confidence, contradictions, or policy decisions.
