import { netrcPath, tailLog } from "./helpers.js";
import * as actionsCore from "@actions/core";
import { DetSysAction, inputs, stringifyError } from "detsys-ts";
import got, { Got, Response } from "got";
import * as http from "http";
import { SpawnOptions, spawn } from "node:child_process";
import { mkdirSync, openSync, readFileSync } from "node:fs";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { inspect } from "node:util";

// The ENV_DAEMON_DIR is intended to determine if we "own" the daemon or not,
// in the case that a user has put the magic nix cache into their workflow
// twice.
const ENV_DAEMON_DIR = "MAGIC_NIX_CACHE_DAEMONDIR";

const FACT_ENV_VARS_PRESENT = "required_env_vars_present";
const FACT_DIFF_STORE_ENABLED = "diff_store";
const FACT_NOOP_MODE = "noop_mode";

const STATE_DAEMONDIR = "MAGIC_NIX_CACHE_DAEMONDIR";
const STATE_STARTED = "MAGIC_NIX_CACHE_STARTED";
const STARTED_HINT = "true";

const TEXT_NOOP =
  "Magic Nix Cache is already running, this workflow job is in noop mode. Is the Magic Nix Cache in the workflow twice?";
const TEXT_TRUST_UNTRUSTED =
  "The Nix daemon does not consider the user running this workflow to be trusted. Magic Nix Cache is disabled.";
const TEXT_TRUST_UNKNOWN =
  "The Nix daemon may not consider the user running this workflow to be trusted. Magic Nix Cache may not start correctly.";

class MagicNixCacheAction extends DetSysAction {
  private hostAndPort: string;
  private diffStore: boolean;
  private httpClient: Got;
  private noopMode: boolean;
  private daemonDir: string;
  private daemonStarted: boolean;

  constructor() {
    super({
      name: "magic-nix-cache",
      fetchStyle: "gh-env-style",
      idsProjectName: "magic-nix-cache-closure",
      requireNix: "warn",
      diagnosticsSuffix: "perf",
    });

    this.hostAndPort = inputs.getString("listen");
    this.diffStore = inputs.getBool("diff-store");

    this.addFact(FACT_DIFF_STORE_ENABLED, this.diffStore);

    this.httpClient = got.extend({
      retry: {
        limit: 1,
        methods: ["POST", "GET", "PUT", "HEAD", "DELETE", "OPTIONS", "TRACE"],
      },
      hooks: {
        beforeRetry: [
          (error, retryCount) => {
            actionsCore.info(
              `Retrying after error ${error.code}, retry #: ${retryCount}`,
            );
          },
        ],
      },
    });

    this.daemonStarted = actionsCore.getState(STATE_STARTED) === STARTED_HINT;

    if (actionsCore.getState(STATE_DAEMONDIR) !== "") {
      this.daemonDir = actionsCore.getState(STATE_DAEMONDIR);
    } else {
      this.daemonDir = this.getTemporaryName();
      mkdirSync(this.daemonDir);
      actionsCore.saveState(STATE_DAEMONDIR, this.daemonDir);
    }

    if (process.env[ENV_DAEMON_DIR] === undefined) {
      this.noopMode = false;
      actionsCore.exportVariable(ENV_DAEMON_DIR, this.daemonDir);
    } else {
      this.noopMode = process.env[ENV_DAEMON_DIR] !== this.daemonDir;
    }
    this.addFact(FACT_NOOP_MODE, this.noopMode);

    this.stapleFile("daemon.log", path.join(this.daemonDir, "daemon.log"));
  }

  async main(): Promise<void> {
    if (this.noopMode) {
      actionsCore.warning(TEXT_NOOP);
      return;
    }

    if (this.nixStoreTrust === "untrusted") {
      actionsCore.warning(TEXT_TRUST_UNTRUSTED);
      return;
    } else if (this.nixStoreTrust === "unknown") {
      actionsCore.info(TEXT_TRUST_UNKNOWN);
    }

    await this.setUpAutoCache();
    await this.notifyAutoCache();
  }

  async post(): Promise<void> {
    if (this.noopMode) {
      actionsCore.debug(TEXT_NOOP);
      return;
    }

    if (this.nixStoreTrust === "untrusted") {
      actionsCore.debug(TEXT_TRUST_UNTRUSTED);
      return;
    } else if (this.nixStoreTrust === "unknown") {
      actionsCore.debug(TEXT_TRUST_UNKNOWN);
    }

    await this.tearDownAutoCache();
  }

  async setUpAutoCache(): Promise<void> {
    const requiredEnv = [
      "ACTIONS_CACHE_URL",
      "ACTIONS_RUNTIME_URL",
      "ACTIONS_RUNTIME_TOKEN",
    ];

    let anyMissing = false;
    for (const n of requiredEnv) {
      if (!process.env.hasOwnProperty(n)) {
        anyMissing = true;
        actionsCore.warning(
          `Disabling automatic caching since required environment ${n} isn't available`,
        );
      }
    }

    this.addFact(FACT_ENV_VARS_PRESENT, !anyMissing);
    if (anyMissing) {
      return;
    }

    if (this.daemonStarted) {
      actionsCore.debug("Already started.");
      return;
    }

    actionsCore.debug(
      `GitHub Action Cache URL: ${process.env["ACTIONS_CACHE_URL"]}`,
    );

    const daemonBin = await this.unpackClosure("magic-nix-cache");

    let runEnv;
    if (actionsCore.isDebug()) {
      runEnv = {
        RUST_LOG: "trace,magic_nix_cache=debug,gha_cache=debug",
        RUST_BACKTRACE: "full",
        ...process.env,
      };
    } else {
      runEnv = process.env;
    }

    const notifyPort = inputs.getString("startup-notification-port");

    const notifyPromise = new Promise<Promise<void>>((resolveListening) => {
      const promise = new Promise<void>(async (resolveQuit) => {
        const notifyServer = http.createServer((req, res) => {
          if (req.method === "POST" && req.url === "/") {
            actionsCore.debug(`Notify server shutting down.`);
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end("{}");
            notifyServer.close(() => {
              resolveQuit();
            });
          }
        });

        notifyServer.listen(notifyPort, () => {
          actionsCore.debug(`Notify server running.`);
          resolveListening(promise);
        });
      });
    });

    // Start tailing the daemon log.
    const outputPath = `${this.daemonDir}/daemon.log`;
    const output = openSync(outputPath, "a");
    const log = tailLog(this.daemonDir);
    const netrc = await netrcPath();
    const nixConfPath = `${process.env["HOME"]}/.config/nix/nix.conf`;
    const upstreamCache = inputs.getString("upstream-cache");
    const diagnosticEndpoint = inputs.getString("diagnostic-endpoint");
    const useFlakeHub = inputs.getBool("use-flakehub");
    const flakeHubCacheServer = inputs.getString("flakehub-cache-server");
    const flakeHubApiServer = inputs.getString("flakehub-api-server");
    const flakeHubFlakeName = inputs.getString("flakehub-flake-name");
    const useGhaCache = inputs.getBool("use-gha-cache");

    const daemonCliFlags: string[] = [
      "--startup-notification-url",
      `http://127.0.0.1:${notifyPort}`,
      "--listen",
      this.hostAndPort,
      "--upstream",
      upstreamCache,
      "--diagnostic-endpoint",
      diagnosticEndpoint,
      "--nix-conf",
      nixConfPath,
    ]
      .concat(this.diffStore ? ["--diff-store"] : [])
      .concat(
        useFlakeHub
          ? [
              "--use-flakehub",
              "--flakehub-cache-server",
              flakeHubCacheServer,
              "--flakehub-api-server",
              flakeHubApiServer,
              "--flakehub-api-server-netrc",
              netrc,
              "--flakehub-flake-name",
              flakeHubFlakeName,
            ]
          : [],
      )
      .concat(useGhaCache ? ["--use-gha-cache"] : []);

    const opts: SpawnOptions = {
      stdio: ["ignore", output, output],
      env: runEnv,
      detached: true,
    };

    // Display the final command for debugging purposes
    actionsCore.debug("Full daemon start command:");
    actionsCore.debug(`${daemonBin} ${daemonCliFlags.join(" ")}`);

    // Start the server. Once it is ready, it will notify us via the notification server.
    const daemon = spawn(daemonBin, daemonCliFlags, opts);

    this.daemonStarted = true;
    actionsCore.saveState(STATE_STARTED, STARTED_HINT);

    const pidFile = path.join(this.daemonDir, "daemon.pid");
    await fs.writeFile(pidFile, `${daemon.pid}`);

    actionsCore.info("Waiting for magic-nix-cache to start...");

    await new Promise<void>((resolve, reject) => {
      notifyPromise
        // eslint-disable-next-line github/no-then
        .then((_value) => {
          resolve();
        })
        // eslint-disable-next-line github/no-then
        .catch((e: unknown) => {
          const msg = stringifyError(e);

          if (this.strictMode) {
            reject(new Error(`error in notifyPromise: ${msg}`));
          } else {
            this.exitWithWarning(`failed to start daemon: ${msg}`);
          }
        });
      daemon.on("exit", async (code, signal) => {
        let msg: string;
        if (signal) {
          msg = `Daemon was killed by signal ${signal}`;
        } else if (code) {
          msg = `Daemon exited with code ${code}`;
        } else {
          msg = "Daemon unexpectedly exited";
        }
        reject(new Error(msg));
      });
    });

    daemon.unref();

    actionsCore.info("Launched Magic Nix Cache");

    log.unwatch();
  }

  private async notifyAutoCache(): Promise<void> {
    if (!this.daemonStarted) {
      actionsCore.debug("magic-nix-cache not started - Skipping");
      return;
    }

    try {
      actionsCore.debug(`Indicating workflow start`);
      const res: Response<string> = await this.httpClient.post(
        `http://${this.hostAndPort}/api/workflow-start`,
      );

      actionsCore.debug(
        `Response from POST to /api/workflow-start: (status: ${res.statusCode}, body: ${res.body})`,
      );

      if (res.statusCode !== 200) {
        throw new Error(
          `Failed to trigger workflow start hook; expected status 200 but got (status: ${res.statusCode}, body: ${res.body})`,
        );
      }

      actionsCore.debug(`back from post: ${res.body}`);
    } catch (e: unknown) {
      if (this.strictMode) {
        actionsCore.setFailed(`Magic Nix Cache failed to start: ${inspect(e)}`);
      } else {
        actionsCore.warning(`Error marking the workflow as started:`);
        actionsCore.warning(inspect(e));
        actionsCore.warning(
          `Magic Nix Cache may not be running for this workflow.`,
        );
      }
    }
  }

  async tearDownAutoCache(): Promise<void> {
    if (!this.daemonStarted) {
      actionsCore.debug("magic-nix-cache not started - Skipping");
      return;
    }

    const pidFile = path.join(this.daemonDir, "daemon.pid");
    const pid = parseInt(await fs.readFile(pidFile, { encoding: "ascii" }));
    actionsCore.debug(`found daemon pid: ${pid}`);
    if (!pid) {
      throw new Error("magic-nix-cache did not start successfully");
    }

    const log = tailLog(this.daemonDir);

    try {
      actionsCore.debug(`about to post to localhost`);
      const res: Response<string> = await this.httpClient.post(
        `http://${this.hostAndPort}/api/workflow-finish`,
      );

      actionsCore.debug(
        `Response from POST to /api/workflow-finish: (status: ${res.statusCode}, body: ${res.body})`,
      );

      if (res.statusCode !== 200) {
        throw new Error(
          `Failed to trigger workflow finish hook; expected status 200 but got (status: ${res.statusCode}, body: ${res.body})`,
        );
      }
    } finally {
      actionsCore.debug(`unwatching the daemon log`);
      log.unwatch();
    }

    actionsCore.debug(`killing`);

    try {
      process.kill(pid, "SIGTERM");
    } catch (e: unknown) {
      if (typeof e === "object" && e && "code" in e && e.code !== "ESRCH") {
        if (this.strictMode) {
          throw e;
        } else {
          this.exitWithWarning(`couldn't kill daemon: ${stringifyError(e)}`);
        }
      }
    } finally {
      if (actionsCore.isDebug()) {
        actionsCore.info("Entire log:");
        const entireLog = readFileSync(path.join(this.daemonDir, "daemon.log"));
        actionsCore.info(entireLog.toString());
      }
    }
  }

  private exitWithWarning(msg: string): void {
    actionsCore.warning(msg);
    actionsCore.warning(`strict mode not enabled; exiting`);
    process.exit(0);
  }
}

function main(): void {
  new MagicNixCacheAction().execute();
}

main();
