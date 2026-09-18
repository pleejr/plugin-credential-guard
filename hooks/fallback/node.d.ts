/**
 * The slice of Node's `process` this fallback uses, declared locally.
 *
 * The plugin's own hooks never touch Node globals — the engine hands them `$` —
 * so `tsconfig.json` deliberately sets `"types": []`. A command hook is a
 * different shape: it is a process, reading stdin and answering with an exit
 * code. Declaring the three members it uses keeps that promise rather than
 * pulling `@types/node` in for one file.
 */
declare const process: {
  readonly stdin: {
    setEncoding(encoding: string): void
    on(event: 'data', listener: (chunk: string) => void): void
    on(event: 'end', listener: () => void): void
  }
  readonly stdout: { write(text: string): boolean }
  readonly stderr: { write(text: string): boolean }
  exit(code: number): never
}
