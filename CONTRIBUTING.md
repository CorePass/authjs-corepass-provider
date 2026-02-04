# Contributing

Thanks for your interest in improving `authjs-corepass-provider`.

## Development setup

### Requirements

- Node.js 24.x
- npm

### Install

```bash
npm i
```

### Build and typecheck

```bash
npm run typecheck
npm run build
```

## Code style

- **TypeScript/JavaScript**: tabs (`tab_width = 4`)
- **YAML/JSON/Markdown/SQL**: spaces (`indent_size = 4`)
- No trailing whitespace, and files should end with a single newline

These are enforced via `.editorconfig`.

## What to include in a PR

- A clear description of the change and motivation
- Any relevant docs updates (most changes should update `README.md`)
- If you add new options, document defaults and security implications

## Releases

Publishing is done via GitHub Releases and the workflow in `.github/workflows/publish.yml`.
It uses npm trusted publishing (`--provenance`) when configured on npm for this package.

## Security

If you find a security issue, please do not open a public issue.
Follow the Auth.js security reporting guidance:

- [Auth.js security reporting guidance](https://authjs.dev/security#reporting-a-vulnerability)
