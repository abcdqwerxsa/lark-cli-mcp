// Wrap the official lark-cli binary: spawn, parse its JSON envelope, trim output.
// Success envelope (stdout): {ok:true, data, meta:{pagination?}, ...}
// Error envelope (stderr, non-zero exit): {ok:false, error:{message, hint, ...}}
import { spawn } from 'node:child_process';

/** @typedef {{timeoutMs?: number, maxOutput?: number, bin?: string}} RunOpts */

/**
 * Run lark-cli, collect stdout/stderr (capped), kill on timeout.
 * @param {string[]} args
 * @param {RunOpts} opts
 * @returns {Promise<{code: number, stdout: string, stderr: string, timedOut: boolean}>}
 */
export function runLarkCli(args, opts = {}) {
  const bin = opts.bin ?? process.env.LARK_CLI_BIN ?? 'lark-cli';
  const timeoutMs = opts.timeoutMs ?? (Number(process.env.LARK_MCP_TIMEOUT_MS) || 120_000);
  const cap = 16 * 1024 * 1024; // hard memory cap on child output
  return new Promise((resolve) => {
    const child = spawn(bin, args, {
      env: { ...process.env, NO_COLOR: '1', FORCE_COLOR: '0', TERM: 'dumb' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    /** @type {[Buffer[], Buffer[]]} */
    const bufs = [[], []];
    let bytes = 0;
    let timedOut = false;
    const capStream = /** @param {Buffer[]} acc */ (acc) => (/** @type {import('node:stream').Readable} */ s) => {
      s.on('data', (/** @type {Buffer} */ d) => {
        bytes += d.length;
        acc.push(d);
        if (bytes > cap) child.kill('SIGKILL');
      });
    };
    capStream(bufs[0])(child.stdout);
    capStream(bufs[1])(child.stderr);
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, timeoutMs);
    timer.unref?.();
    child.on('error', (err) => {
      // bin not found / not executable
      clearTimeout(timer);
      resolve({ code: 127, stdout: '', stderr: String(err), timedOut: false });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({
        code: code ?? 1,
        stdout: Buffer.concat(bufs[0]).toString('utf8'),
        stderr: Buffer.concat(bufs[1]).toString('utf8'),
        timedOut,
      });
    });
  });
}

/**
 * Clip a string to maxBytes (UTF-8), appending a note when truncated.
 * Token-saving guardrail: LLM clients pay for every byte returned.
 */
export function clip(/** @type {string} */ s, maxBytes) {
  const bytes = Buffer.byteLength(s);
  if (bytes <= maxBytes) return { text: s, truncated: false, bytes };
  const cut = Buffer.from(s).subarray(0, maxBytes).toString('utf8');
  return {
    text: `${cut}\n[truncated ${bytes} -> ${maxBytes} bytes; narrow the result with jq/params or raise LARK_MCP_MAX_OUTPUT]`,
    truncated: true,
    bytes,
  };
}

/**
 * lark-cli applies --jq to the whole envelope {ok, data, meta}, so an LLM's
 * natural `.name` / `{name, open_id}` silently yields null. Evaluate user jq in
 * the `.data` context instead: `.data | (<expr>)`. Expressions that already
 * address the envelope (start with `.data`, `.ok`, `.meta`, or `.`) are kept as-is.
 */
export function scopeJq(/** @type {string} */ expr) {
  const e = expr.trim();
  if (/^\.(data|ok|meta|_)\b/.test(e)) return e; // already envelope-aware
  if (e === '.') return '.data';
  if (e.startsWith('.[')) return `.data${e.slice(1)}`; // `.[0]` -> `.data[0]`
  return `.data | (${e})`;
}

/**
 * Map MCP tool input to lark-cli api argv.
 * @param {{method: string, path: string, as?: 'user'|'bot', params?: object, data?: object, jq?: string, page_all?: boolean, page_limit?: number}} input
 */
export function buildApiArgs(input) {
  const args = ['api', input.method.toUpperCase(), input.path]; // --format json is the default
  if (input.as) args.push('--as', input.as); // user | bot (default auto: user when logged in)
  if (input.params !== undefined) args.push('--params', JSON.stringify(input.params));
  if (input.data !== undefined) args.push('--data', JSON.stringify(input.data));
  if (input.jq) args.push('--jq', scopeJq(input.jq));
  if (input.page_all) args.push('--page-all');
  if (input.page_limit !== undefined) args.push('--page-limit', String(input.page_limit));
  return args;
}

/**
 * Turn a finished lark-cli run into an MCP tool result (envelope unwrapping).
 * Success -> data only (+ pagination when present). Failure -> compact error.
 */
export function toToolResult(
  /** @type {{code: number, stdout: string, stderr: string, timedOut: boolean}} */ run,
  /** @type {number} */ maxOutput,
) {
  if (run.timedOut) {
    return { content: [{ type: 'text', text: `lark-cli timed out (LARK_MCP_TIMEOUT_MS)` }], isError: true };
  }
  // Success path: unwrap {ok, data, meta}. With --jq, lark-cli emits the bare
  // filtered value(s) instead of an envelope, so a zero exit code is the real
  // success signal and we pass that output through as-is.
  if (run.code === 0) {
    const out = run.stdout.trim();
    try {
      const env = JSON.parse(out);
      if (env && env.ok === true) {
        let data = env.data ?? null;
        const pag = env.meta?.pagination;
        if (pag) {
          data = data !== null && typeof data === 'object' && !Array.isArray(data)
            ? { ...data, _pagination: pag }
            : { data, _pagination: pag };
        }
        const c = clip(JSON.stringify(data), maxOutput);
        return { content: [{ type: 'text', text: c.text }] };
      }
    } catch {
      // not a single JSON doc (jq can stream several values) — pass through below
    }
    const c = clip(out || '(empty result)', maxOutput);
    return { content: [{ type: 'text', text: c.text }] };
  }
  // Error path: prefer the typed stderr envelope
  let text = run.stderr.trim() || run.stdout.trim() || `lark-cli exited with code ${run.code}`;
  try {
    const errEnv = JSON.parse(text);
    if (errEnv && errEnv.ok === false && errEnv.error) {
      const e = errEnv.error;
      text = JSON.stringify(e);
    }
  } catch {
    /* raw text */
  }
  const c = clip(text, Math.min(maxOutput, 16 * 1024));
  return { content: [{ type: 'text', text: c.text }], isError: true };
}

/**
 * MCP tool handler: lark_api — call any Feishu Open API.
 * @param {Parameters<import('./lark.mjs').runLarkCli>[1] | undefined} _runOpts
 */
export async function larkApiTool(/** @type {any} */ input, _runOpts = undefined) {
  const maxOutput = Number(process.env.LARK_MCP_MAX_OUTPUT) || 65_536;
  const run = await runLarkCli(buildApiArgs(input), _runOpts ?? {});
  return toToolResult(run, maxOutput);
}

/** MCP tool handler: lark_auth_status — server-side lark-cli auth state. */
export async function larkAuthStatusTool() {
  const maxOutput = Number(process.env.LARK_MCP_MAX_OUTPUT) || 65_536;
  const run = await runLarkCli(['auth', 'status', '--json']);
  const c = clip(run.stdout.trim() || run.stderr.trim() || `exit ${run.code}`, maxOutput);
  return { content: [{ type: 'text', text: c.text }], isError: run.code !== 0 };
}
