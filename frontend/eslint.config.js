import svelte from "@anarkisti/eslint-config/svelte";

import svelteConfig from "./svelte.config.js";

export default [...svelte(svelteConfig), { ignores: ["dist/", ".svelte-kit/"] }];
