import { defineConfig } from 'vite';

export default defineConfig({
    // Relative base: the same bundle serves at the domain root AND under the
    // GitHub Pages /<repo>/ subpath.
    base: './',
    build: {
        // Deliberately UNMINIFIED: the deployed page's JS stays readable and
        // diffable against this repository's source. A minified artifact is
        // not verifiable — it reintroduces exactly the trust this tool
        // exists to remove. The app is small; there is no performance case.
        minify: false,
        outDir: 'dist',
    },
});
