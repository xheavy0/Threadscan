# vulnapp: threat model

A small HTTP service (`app.py`, Python standard library) that serves files from `public/`
and offers two admin endpoints.

## Working in the scan image

- Source at `/src`; run the app with `python app.py --port 8080 &`, wait for
  `curl -s localhost:8080/health`, then send requests with `curl`.
- Tests: `python -m unittest discover -s tests`.

## Untrusted input

Everything in an HTTP request: path, query string and headers. Clients are anonymous unless
they send the admin token in `X-Admin-Token`.

## What must hold

- `/files` serves only files inside `public/`. Any file outside it (for example
  `/src/secret.txt`) must never be returned.
- Every `/admin/*` endpoint requires a valid `X-Admin-Token`.

## Severity

- **High**: reading a file outside `public/`; reading admin data without the token.
- **Medium**: information disclosure with little value.
- **Low**: hardening.

Nothing is out of scope; there are no accepted risks.
