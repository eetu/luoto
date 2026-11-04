# frontend

SvelteKit (runes) SPA, adapter-static to `dist/`, embedded into `luoto` by rust-embed (the
`cli/build.rs` re-embeds on rebuild). halo-design tokens in `src/lib/styles/halo.css`
(verbatim copy of the family file); halo-interaction shell: env list (navigate), egress view
(surface), subject panel (host, request, env or vault) and status bar.

- `src/lib/api.ts` is the only fetch layer; types in `src/lib/types.ts` mirror the Rust
  structs by hand. The token comes from the `#token=` fragment into sessionStorage.
- Shared state lives in `src/lib/stores/app.svelte.ts`; panels read it directly.
- Live updates: fetch-based SSE (`followEvents`) so the token can travel in a header.
- One context menu (`menu.svelte.ts` + `ContextMenu.svelte`), one `Modal`.
- Text written by the sandbox (request reasons) is rendered as plain text in an
  "untrusted" block — never as HTML, never pre-filled into commands.
- `yarn validate` = typecheck + lint + format. Vendored yarn: `node .yarn/releases/yarn-*.cjs`.
- Glyph: the islet outline is the accent (orange stroke over currentColor waves) instead of the
  family's warm dot, which read as a figure above the islet. Still exactly one accent element.
