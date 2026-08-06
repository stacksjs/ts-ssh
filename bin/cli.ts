/**
 * Reading keys, from a terminal.
 *
 * The library is the product. This exists because `authorized_keys` is a file
 * people edit by hand and get wrong, and a tool that says exactly what a line
 * parses to - or that it does not parse at all - is worth having.
 */

import { CLI } from '@stacksjs/clapp'
import { version } from '../package.json'
import { parseAuthorizedKey, parseAuthorizedKeys } from '../src/keys'

const cli = new CLI('ts-ssh')

cli
  .command('keys <file>', 'Read an authorized_keys file and say what is in it')
  .example('ts-ssh keys ~/.ssh/authorized_keys')
  .action(async (file: string) => {
    const text = await Bun.file(file).text()
    const keys = parseAuthorizedKeys(text)
    const lines = text.split('\n').filter(line => line.trim() !== '' && !line.trim().startsWith('#'))

    for (const key of keys) {
      const bits = key.bits ? `${key.bits} ` : ''
      console.log(`${bits}${key.fingerprint} ${key.comment || '(no comment)'} (${key.type})`)
      if (key.options)
        console.log(`  options: ${key.options}`)
    }

    // Said out loud rather than left to be noticed: a line this cannot read is
    // a key that will not let somebody in, and silence about it is the worst
    // possible answer.
    if (keys.length < lines.length)
      console.log(`\n${lines.length - keys.length} line(s) could not be read as a key`)
  })

cli
  .command('fingerprint <line>', 'Fingerprint one authorized_keys line')
  .action((line: string) => {
    const key = parseAuthorizedKey(line)

    if (!key) {
      console.error('That is not a key this can read')
      process.exitCode = 1

      return
    }

    console.log(key.fingerprint)
  })

cli.command('version', 'Show the version').action(() => console.log(version))

cli.version(version)
cli.help()
cli.parse()
