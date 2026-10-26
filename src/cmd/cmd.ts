import yargs, { type Argv } from 'yargs';
import { hideBin } from 'yargs/helpers';
import {
  connectStdioTransport,
  connectHttpTransport,
  connectSSETransport,
  type TransportOptions
} from '../server/transport.js';
import { DEFAULT_BIND_ADDRESS } from '../server/security.js';
import { logger } from '../logging/logging.js';

// The transport entrypoints, injectable so the CLI wiring can be tested without
// starting real servers.
export interface Transports {
  connectStdioTransport: () => void | Promise<void>;
  connectSSETransport: (options: TransportOptions) => unknown;
  connectHttpTransport: (options: TransportOptions & { stateless?: boolean }) => unknown;
}

const defaultTransports: Transports = {
  connectStdioTransport,
  connectSSETransport,
  connectHttpTransport
};

// Options shared by the two network transports. The inbound token is env-only:
// argv is readable by every user on the machine via `ps`.
// Not generic: this fork's yargs typings fail overload resolution on a generic
// builder passed to command(); a plain Argv parameter infers the same option set.
const listenerOptions = (yargs: Argv) =>
  yargs
    .option('port', {
      type: 'number',
      default: 3000
    })
    // This decides who may connect. --allowed-host-header only checks what an
    // already-connected client claims, which is why they are not named as a pair.
    .option('bind-address', {
      type: 'string',
      default: process.env.MCP_BIND_ADDRESS || DEFAULT_BIND_ADDRESS,
      description:
        'Address to listen on. Defaults to loopback; widening it exposes every ArgoCD tool to the network and requires MCP_AUTH_TOKEN, --allow-unauthenticated, or AUTH_MODE=oidc.'
    })
    .option('allowed-host-header', {
      type: 'array',
      string: true,
      default: [] as string[],
      description:
        'Additional hostname accepted in a request Host header. Does not control who may connect. Repeatable. Loopback names, and in oidc mode the MCP_PUBLIC_URL host, are always accepted.'
    })
    .option('allowed-origin', {
      type: 'array',
      string: true,
      default: [] as string[],
      description:
        'Additional browser origin accepted in the Origin header, e.g. https://ide.example. Repeatable. Loopback origins on this port are always accepted.'
    })
    // An array option is greedy: '--allowed-host-header a.example stateless' would
    // allow-list 'stateless' too. One value per occurrence.
    .nargs('allowed-host-header', 1)
    .nargs('allowed-origin', 1)
    .option('allow-unauthenticated', {
      type: 'boolean',
      default: false,
      description:
        'Permit a non-loopback bind without MCP_AUTH_TOKEN. Only use this when the listener is already protected by an external layer.'
    })
    // Without this, '--port abc' reaches the Origin allow-list builder as NaN and
    // fails there as a bare 'Invalid URL'. Port 0 is rejected because that list is
    // port-specific and would be pinned to ':0' while the kernel hands out a real one.
    .check(({ port }) => {
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        // yargs has already coerced a non-numeric value to NaN, so the original
        // text is gone by now.
        const shown = Number.isNaN(port) ? 'not a number' : port;
        throw new Error(`Invalid --port value: ${shown}. Expected an integer between 1 and 65535.`);
      }
      return true;
    });

type ListenerArgv = {
  port: number;
  bindAddress: string;
  allowedHostHeader: string[];
  allowedOrigin: string[];
  allowUnauthenticated: boolean;
};

const transportOptions = (argv: ListenerArgv): TransportOptions => ({
  port: argv.port,
  bindAddress: argv.bindAddress,
  allowedHostHeaders: argv.allowedHostHeader,
  allowedOrigins: argv.allowedOrigin,
  authToken: process.env.MCP_AUTH_TOKEN,
  allowUnauthenticated: argv.allowUnauthenticated
});

// Build the parser and run it. Uses parseAsync (never parseSync): the http
// transport is async and, in oidc mode, suspends on a top-level `await` during
// OIDC discovery — parseSync throws the moment a handler returns a pending
// promise. A listener-security error thrown by a transport rejects the same
// promise, and cmd() below reports it as a startup error.
// async so that a parse failure yargs raises synchronously (exitProcess(false)
// makes it throw a YError) still surfaces as a rejection of the returned promise.
export const runCmd = async (
  argv: string[],
  transports: Transports = defaultTransports
): Promise<unknown> => {
  const exe = yargs(argv);

  exe.command(
    'stdio',
    'Start ArgoCD MCP server using stdio.',
    () => {},
    () => transports.connectStdioTransport()
  );

  // Handlers return Promise<void> (yargs' handler type); the transports' own
  // return values (the listening server) are awaited and dropped here.
  exe.command('sse', 'Start ArgoCD MCP server using SSE.', listenerOptions, async (argv) => {
    await transports.connectSSETransport(transportOptions(argv));
  });

  exe.command(
    'http',
    'Start ArgoCD MCP server using Http Stream.',
    (yargs) =>
      listenerOptions(yargs).option('stateless', {
        type: 'boolean',
        default: false,
        description: 'Run in stateless mode'
      }),
    async (argv) => {
      await transports.connectHttpTransport({
        ...transportOptions(argv),
        stateless: argv.stateless
      });
    }
  );

  // Without strict(), a misspelled security flag ('--allowed-host') is silently
  // absorbed and the listener starts with that protection off. exitProcess(false)
  // turns a parse failure into a rejection of this promise, which cmd() reports
  // and exits on, instead of yargs calling process.exit from inside the parser.
  return exe.strict().exitProcess(false).demandCommand().parseAsync();
};

export const cmd = (): Promise<void> =>
  runCmd(hideBin(process.argv)).then(
    () => {},
    (error: unknown) => {
      logger.error(
        { error: error instanceof Error ? error.message : String(error) },
        'Failed to start ArgoCD MCP server'
      );
      process.exit(1);
    }
  );
