import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';
import {
  connectStdioTransport,
  connectHttpTransport,
  connectSSETransport
} from '../server/transport.js';
import { logger } from '../logging/logging.js';

// The transport entrypoints, injectable so the CLI wiring can be tested without
// starting real servers.
export interface Transports {
  connectStdioTransport: () => void | Promise<void>;
  connectSSETransport: (port: number) => void | Promise<void>;
  connectHttpTransport: (port: number, stateless: boolean) => void | Promise<void>;
}

const defaultTransports: Transports = {
  connectStdioTransport,
  connectSSETransport,
  connectHttpTransport
};

// Build the parser and run it. Uses parseAsync (never parseSync): the http
// transport is async and, in oidc mode, suspends on a top-level `await` during
// OIDC discovery — parseSync throws the moment a handler returns a pending
// promise.
export const runCmd = (
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

  exe.command(
    'sse',
    'Start ArgoCD MCP server using SSE.',
    (yargs) => {
      return yargs.option('port', {
        type: 'number',
        default: 3000
      });
    },
    ({ port }) => transports.connectSSETransport(port)
  );

  exe.command(
    'http',
    'Start ArgoCD MCP server using Http Stream.',
    (yargs) => {
      return yargs
        .option('port', {
          type: 'number',
          default: 3000
        })
        .option('stateless', {
          type: 'boolean',
          default: false,
          description: 'Run in stateless mode'
        });
    },
    ({ port, stateless }) => transports.connectHttpTransport(port, stateless)
  );

  return exe.demandCommand().parseAsync();
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
