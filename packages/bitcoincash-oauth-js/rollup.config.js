import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import terser from '@rollup/plugin-terser';

const pkg = {
  name: 'bitcoincash-oauth-client',
  version: '1.0.0'
};

export default [
  // ES Module build (for modern Node.js and bundlers)
  {
    input: 'src/index.js',
    output: {
      file: 'dist/index.mjs',
      format: 'es',
      exports: 'named',
      banner: `/**
 * ${pkg.name} v${pkg.version}
 * Universal Bitcoin Cash OAuth Client
 * Works in both browser and Node.js environments
 */`
    },
    external: ['@bitauth/libauth', 'crypto', 'node-fetch'],
    plugins: [
      resolve({
        preferBuiltins: true
      }),
      commonjs()
    ]
  },
  
  // CommonJS build (for older Node.js)
  {
    input: 'src/index.js',
    output: {
      file: 'dist/index.cjs',
      format: 'cjs',
      exports: 'named',
      banner: `/**
 * ${pkg.name} v${pkg.version}
 * Universal Bitcoin Cash OAuth Client
 * Works in both browser and Node.js environments
 */`,
      interop: 'auto'
    },
    external: ['@bitauth/libauth', 'crypto', 'node-fetch'],
    plugins: [
      resolve({
        preferBuiltins: true
      }),
      commonjs()
    ]
  },
  
  // Browser build (bundled, minified)
  {
    input: 'src/index.js',
    output: {
      file: 'dist/index.browser.min.js',
      format: 'umd',
      name: 'BitcoinCashOAuthClient',
      exports: 'named',
      banner: `/**
 * ${pkg.name} v${pkg.version}
 * Universal Bitcoin Cash OAuth Client
 * Browser build - includes all dependencies
 */`,
      globals: {
        '@bitauth/libauth': 'libauth'
      }
    },
    external: [],
    plugins: [
      resolve({
        browser: true,
        preferBuiltins: false
      }),
      commonjs(),
      terser({
        output: {
          comments: /^!/
        }
      })
    ]
  }
];
