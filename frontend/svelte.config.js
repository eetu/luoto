import adapter from "@sveltejs/adapter-static";

/** @type {import('@sveltejs/kit').Config} */
const config = {
  compilerOptions: {
    // Force runes mode (Svelte 5). Can be removed in Svelte 6.
    runes: ({ filename }) => (filename.split(/[/\\]/).includes("node_modules") ? undefined : true),
  },
  kit: {
    // Pure SPA, embedded into the luoto binary (rust-embed of dist/) and served with
    // index.html as the fallback for every unmatched path. See spa-frontend / rust-axum.
    adapter: adapter({
      pages: "dist",
      assets: "dist",
      fallback: "index.html",
      precompress: false,
      strict: true,
    }),
    // The e2e fixtures are typed against the generated API types; the specs need Node's
    // types, which this project doesn't install.
    typescript: {
      config: (config) => {
        config.include.push("../e2e/fixtures/**/*.ts");
      },
    },
  },
};

export default config;
