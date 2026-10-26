# Contributing to LogShield

Thanks for helping people share logs more carefully.

## Development

Use Node.js 20+. Run `npm start` and `npm test`; there is no dependency installation or build step. Keep the static browser bundle dependency-free. Test only with fictional credentials and non-personal data.

## Detection changes

Add a failing test before changing a detector. Include a positive example, a harmless negative example, and an overlapping match when relevant. Preserve offsets and JSON validity. Do not turn a pattern match into a claim that a credential is valid. Document any new limits.

## Privacy invariants

Do not introduce uploads, analytics, remote fonts, third-party scripts, browser persistence, or automatic clipboard access. Never render user input through `innerHTML`. Do not put matched values in metadata summaries, diagnostics, screenshots, issues, or test output.

## Useful contributions

- Regression fixtures for common log formats, using fake data.
- Accessibility and keyboard navigation improvements.
- English / Spanish wording corrections.
- Better precision without increasing accidental disclosure.

For a security issue, follow [SECURITY.md](SECURITY.md). Keep changes small and explain the behavior being fixed.
