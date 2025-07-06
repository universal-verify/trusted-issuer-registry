import terser from '@rollup/plugin-terser';
import { nodeResolve } from '@rollup/plugin-node-resolve';

export default [
    {
        input: 'scripts/trusted-issuer-registry.js',
        output: [{
            file: 'build/trusted-issuer-registry.js',
            format: 'es',
        }, {
            file: 'build/trusted-issuer-registry.min.js',
            format: 'es',
            plugins: [
                terser({ mangle: { keep_classnames: true, keep_fnames: true }}),
            ],
        }],
    }, {
        input: 'scripts/trusted-issuer-registry.js',
        output: [{
            file: 'build/trusted-issuer-registry.bundled.js',
            format: 'es',
        }, {
            file: 'build/trusted-issuer-registry.bundled.min.js',
            format: 'es',
            plugins: [
                terser({ mangle: { keep_classnames: true, keep_fnames: true }}),
            ],
        }],
        plugins: [nodeResolve()],
    }
];
