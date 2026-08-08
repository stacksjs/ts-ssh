import { dts } from 'bun-plugin-dtsx'

await Bun.build({
  entrypoints: ['src/index.ts'],
  outdir: './dist',
  target: 'bun',
  plugins: [dts()],
})

/**
 * The CLI, as JavaScript, at the path `package.json` promises.
 *
 * `bin` points at `dist/bin/cli.js` and nothing was building it: `compile`
 * produces a native executable at `bin/ts-ssh`, which is a different artifact
 * for a different job (a GitHub release asset) and is not in `files` anyway.
 * So the published package declared a command that resolved to a missing file,
 * and `bunx @stacksjs/ts-ssh` failed on a package that had installed cleanly.
 *
 * Its own build call rather than a second entrypoint on the one above, because
 * Bun derives the output layout from the common root of all entrypoints:
 * adding `bin/cli.ts` there would move the library to `dist/src/index.js` and
 * break the `exports` map to fix the `bin` one.
 */
await Bun.build({
  entrypoints: ['bin/cli.ts'],
  outdir: './dist/bin',
  target: 'bun',
  // Without this the file is not executable as a command, whatever the
  // permissions say.
  banner: '#!/usr/bin/env bun',
})
