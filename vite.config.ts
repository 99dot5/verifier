/// <reference types='vitest' />
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
    test: {
        // STATED, not inherited from vitest's default. Every suite here is
        // pure maths and wire decoding with no DOM under test, and the vector
        // tests resolve ../../vectors/*.json through import.meta.url — which
        // jsdom breaks (its import.meta.url does not survive fileURLToPath).
        // The monorepo's own config says the same thing; leaving it implicit
        // here made the exported tree pass by accident.
        environment: 'node',
        include: ['src/**/*.{test,spec}.ts'],
    },
});
