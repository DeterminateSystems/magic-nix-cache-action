import { getTrinaryInput, netrcPath, tailLog } from "./helpers.js";
//import { warnOnMnc } from "./mnc-warn.js";
import * as actionsCore from "@actions/core";
import * as actionsGithub from "@actions/github";
import {
  DetSysAction,
  inputs,
  log,
  stringifyError,
  withSpan,
} from "@determinate-systems/detsys-ts";
import got, { Got, Response } from "got";
import * as http from "http";
import { SpawnOptions, spawn } from "node:child_process";
import { mkdirSync, openSync, readFileSync } from "node:fs";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { setTimeout } from "node:timers/promises";

// The ENV_DAEMON_DIR is intended to determine if we "own" the daemon or not,
// in the case that a user has put the magic nix cache into their workflow
// twice.
const ENV_DAEMON_DIR = "MAGIC_NIX_CACHE_DAEMONDIR";

const ENV_MNC_ADDR = "MAGIC_NIX_CACHE_ADDRESS";

const ATTR_ENV_VARS_PRESENT =
  "detsys.magic_nix_cache.required_env_vars_present";
const ATTR_SENT_SIGTERM = "detsys.magic_nix_cache.sent_sigterm";
const ATTR_DIFF_STORE_ENABLED = "detsys.magic_nix_cache.diff_store";
const ATTR_ALREADY_RUNNING = "detsys.magic_nix_cache.noop_mode";
const ATTR_USE_FLAKEHUB = "detsys.magic_nix_cache.use_flakehub";
const ATTR_USE_GHA_CACHE = "detsys.magic_nix_cache.use_gha_cache";
const ATTR_DAEMON_ALREADY_STARTED =
  "detsys.magic_nix_cache.daemon_already_started";
const ATTR_DAEMON_PID = "detsys.magic_nix_cache.daemon_pid";
const ATTR_STATUS_CODE = "detsys.status_code";

const STATE_DAEMONDIR = "MAGIC_NIX_CACHE_DAEMONDIR";
const STATE_ERROR_IN_MAIN = "ERROR_IN_MAIN";
const STATE_STARTED = "MAGIC_NIX_CACHE_STARTED";
const STARTED_HINT = "true";

const TEXT_ALREADY_RUNNING =
  "Magic Nix Cache is already running, this workflow job is in noop mode. Is the Magic Nix Cache in the workflow twice?";
const TEXT_TRUST_UNTRUSTED =
  "The Nix daemon does not consider the user running this workflow to be trusted. Magic Nix Cache is disabled.";
const TEXT_TRUST_UNKNOWN =
  "The Nix daemon may not consider the user running this workflow to be trusted. Magic Nix Cache may not start correctly.";

class MagicNixCacheAction extends DetSysAction {
  private hostAndPort: string;
  private diffStore: boolean;
  private httpClient: Got;
  private daemonDir: string;
  private daemonStarted: boolean;

  // This is set to `true` if the MNC is already running, in which case the
  // workflow will use the existing process rather than starting a new one.
  private alreadyRunning: boolean;

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

    this.setAttribute(ATTR_DIFF_STORE_ENABLED, this.diffStore);

    this.httpClient = got.extend({
      retry: {
        limit: 1,
        methods: ["POST", "GET", "PUT", "HEAD", "DELETE", "OPTIONS", "TRACE"],
      },
      hooks: {
        beforeRetry: [
          (error, retryCount) => {
            log.info(
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
      this.alreadyRunning = false;
      actionsCore.exportVariable(ENV_DAEMON_DIR, this.daemonDir);
    } else {
      this.alreadyRunning = process.env[ENV_DAEMON_DIR] !== this.daemonDir;
    }
    this.setAttribute(ATTR_ALREADY_RUNNING, this.alreadyRunning);

    if (process.env[ENV_MNC_ADDR] !== undefined) {
      this.hostAndPort = process.env[ENV_MNC_ADDR];
      actionsCore.exportVariable(ENV_MNC_ADDR, this.hostAndPort);
    }

    this.stapleFile("daemon.log", path.join(this.daemonDir, "daemon.log"));
  }

  async main(): Promise<void> {
    if (this.alreadyRunning) {
      log.warning(TEXT_ALREADY_RUNNING);
      return;
    }

    /**
     * Now that Magic Nix Cache Action support has been restored, we no longer need to
     * throw this warning but we'll make this a comment in case we need to change its
     * status again
     */

    /*
    if (this.getFeature("warn-magic-nix-cache-eol")?.variant === true) {
      await warnOnMnc();
    }
    */

    if (this.nixStoreTrust === "untrusted") {
      log.warning(TEXT_TRUST_UNTRUSTED);
      return;
    } else if (this.nixStoreTrust === "unknown") {
      log.info(TEXT_TRUST_UNKNOWN);
    }

    await this.setUpAutoCache();
    await this.notifyAutoCache();
  }

  async post(): Promise<void> {
    // If strict mode is off and there was an error in main, such as the daemon not starting,
    // then the post phase is skipped with a warning.
    if (!this.strictMode && this.errorInMain) {
      log.warning(
        `skipping post phase due to error in main phase: ${this.errorInMain}`,
      );
      return;
    }

    if (this.alreadyRunning) {
      log.debug(TEXT_ALREADY_RUNNING);
      return;
    }

    if (this.nixStoreTrust === "untrusted") {
      log.debug(TEXT_TRUST_UNTRUSTED);
      return;
    } else if (this.nixStoreTrust === "unknown") {
      log.debug(TEXT_TRUST_UNKNOWN);
    }

    await this.tearDownAutoCache();
  }

  async setUpAutoCache(): Promise<void> {
    return withSpan("set_up_auto_cache", async (span) => {
      const requiredEnv = [
        "ACTIONS_CACHE_URL",
        "ACTIONS_RUNTIME_URL",
        "ACTIONS_RUNTIME_TOKEN",
      ];

      let anyMissing = false;
      for (const n of requiredEnv) {
        if (!process.env.hasOwnProperty(n)) {
          anyMissing = true;
          log.warning(
            `Disabling automatic caching since required environment ${n} isn't available`,
          );
        }
      }

      this.setAttribute(ATTR_ENV_VARS_PRESENT, !anyMissing);
      if (anyMissing) {
        return;
      }

      span.setAttribute(ATTR_DAEMON_ALREADY_STARTED, this.daemonStarted);

      if (this.daemonStarted) {
        log.debug("Already started.");
        return;
      }

      log.debug(`GitHub Action Cache URL: ${process.env["ACTIONS_CACHE_URL"]}`);

      const daemonBin = await this.unpackClosure("magic-nix-cache");

      const extraEnv = {
        GITHUB_CONTEXT: JSON.stringify(actionsGithub.context),
      };
      // Telemetry environment goes last so it wins: it propagates this Action's
      // trace context into the daemon, so the daemon's spans join this trace.
      const telemetryEnv = await this.getTelemetryEnvironment();
      let runEnv = {};
      if (actionsCore.isDebug()) {
        runEnv = {
          RUST_LOG: "debug,magic_nix_cache=trace,gha_cache=trace",
          RUST_BACKTRACE: "full",
          ...process.env,
          ...extraEnv,
          ...telemetryEnv,
        };
      } else {
        runEnv = {
          ...process.env,
          ...extraEnv,
          ...telemetryEnv,
        };
      }

      const notifyPromise = new Promise<[Promise<string>, string]>(
        (resolveListening, rejectListening) => {
          const promise = new Promise<string>((resolveQuit, rejectQuit) => {
            const notifyServer = http.createServer((req, res) => {
              if (req.method === "POST" && req.url === "/") {
                const data: Buffer[] = [];
                req.on("data", (chunk) => {
                  data.push(chunk);
                });

                req.on("end", () => {
                  try {
                    const body = JSON.parse(Buffer.concat(data).toString()) as {
                      address: string;
                    };

                    log.debug(`Notify server shutting down.`);

                    res.writeHead(200, { "Content-Type": "application/json" });
                    res.end("{}");

                    notifyServer.close(() => {
                      resolveQuit(body.address);
                    });
                  } catch (e) {
                    rejectQuit(e);
                  }
                });
              }
            });

            notifyServer.listen(
              inputs.getString("startup-notification-port"),
              () => {
                log.debug(`Notify server running.`);
                const addr = notifyServer.address();
                if (typeof addr === "string") {
                  resolveListening([promise, addr]);
                } else if (addr !== null) {
                  resolveListening([promise, `http://127.0.0.1:${addr.port}`]);
                } else {
                  rejectListening(
                    new Error("Server failed to start correctly"),
                  );
                }
              },
            );
          });
        },
      );

      // Start tailing the daemon log.
      const outputPath = `${this.daemonDir}/daemon.log`;
      const output = openSync(outputPath, "a");
      const daemonLog = tailLog(this.daemonDir);
      const netrc = await netrcPath();
      const nixConfPath = `${process.env["HOME"]}/.config/nix/nix.conf`;
      const upstreamCache = inputs.getString("upstream-cache");
      const useFlakeHub = getTrinaryInput("use-flakehub");
      const flakeHubCacheServer = inputs.getString("flakehub-cache-server");
      const flakeHubApiServer = inputs.getString("flakehub-api-server");
      const flakeHubFlakeName = inputs.getString("flakehub-flake-name");
      const useGhaCache = getTrinaryInput("use-gha-cache");

      span.setAttribute(ATTR_USE_FLAKEHUB, useFlakeHub);
      span.setAttribute(ATTR_USE_GHA_CACHE, useGhaCache);

      await new Promise<void>((resolve) => {
        notifyPromise
          // eslint-disable-next-line github/no-then
          .then(async (promiseResult) => {
            const daemonCliFlags: string[] = [
              "--startup-notification-url",
              promiseResult[1],
              "--listen",
              this.hostAndPort,
              "--upstream",
              upstreamCache,
              "--diagnostic-endpoint",
              (await this.getDiagnosticsUrl())?.toString() ?? "",
              "--nix-conf",
              nixConfPath,
              "--use-gha-cache",
              useGhaCache,
              "--use-flakehub",
              useFlakeHub,
            ]
              .concat(this.diffStore ? ["--diff-store"] : [])
              .concat(
                useFlakeHub !== "disabled"
                  ? [
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
              );

            const opts: SpawnOptions = {
              stdio: ["ignore", output, output],
              env: runEnv,
              detached: true,
            };

            // Display the final command for debugging purposes
            log.debug("Full daemon start command:");
            log.debug(`${daemonBin} ${daemonCliFlags.join(" ")}`);

            // Start the server. Once it is ready, it will notify us via the notification server.
            const daemon = spawn(daemonBin, daemonCliFlags, opts);

            this.daemonStarted = true;
            actionsCore.saveState(STATE_STARTED, STARTED_HINT);

            if (daemon.pid !== undefined) {
              span.setAttribute(ATTR_DAEMON_PID, daemon.pid);
            }

            const pidFile = path.join(this.daemonDir, "daemon.pid");
            await fs.writeFile(pidFile, `${daemon.pid}`);

            log.info("Waiting for magic-nix-cache to start...");

            this.hostAndPort = await promiseResult[0];
            actionsCore.exportVariable(ENV_MNC_ADDR, this.hostAndPort);
            resolve();

            daemon.on("exit", (code, signal) => {
              let msg: string;
              if (signal) {
                msg = `Daemon was killed by signal ${signal}`;
              } else if (code) {
                msg = `Daemon exited with code ${code}`;
              } else {
                msg = "Daemon unexpectedly exited";
              }

              this.exitMain(msg);
            });

            daemon.unref();
          })
          // eslint-disable-next-line github/no-then
          .catch((e: unknown) => {
            this.exitMain(`Error in notifyPromise: ${stringifyError(e)}`);
          });
      });

      log.info("Launched Magic Nix Cache");

      daemonLog.unwatch();
    });
  }

  private async notifyAutoCache(): Promise<void> {
    return withSpan("notify_auto_cache", async (span) => {
      if (!this.daemonStarted) {
        log.debug("magic-nix-cache not started - Skipping");
        return;
      }

      try {
        log.debug(`Indicating workflow start`);
        const res: Response<string> = await this.httpClient.post(
          `http://${this.hostAndPort}/api/workflow-start`,
        );

        span.setAttribute(ATTR_STATUS_CODE, res.statusCode);

        log.debug(
          `Response from POST to /api/workflow-start: (status: ${res.statusCode}, body: ${res.body})`,
        );

        if (res.statusCode !== 200) {
          throw new Error(
            `Failed to trigger workflow start hook; expected status 200 but got (status: ${res.statusCode}, body: ${res.body})`,
          );
        }

        log.debug(`back from post: ${res.body}`);
      } catch (e: unknown) {
        this.exitMain(
          `Error starting the Magic Nix Cache: ${stringifyError(e)}`,
        );
      }
    });
  }

  async tearDownAutoCache(): Promise<void> {
    return withSpan("tear_down_auto_cache", async (span) => {
      if (!this.daemonStarted) {
        log.debug("magic-nix-cache not started - Skipping");
        return;
      }

      const pidFile = path.join(this.daemonDir, "daemon.pid");
      const pid = parseInt(await fs.readFile(pidFile, { encoding: "ascii" }));
      log.debug(`found daemon pid: ${pid}`);
      if (!pid) {
        throw new Error("magic-nix-cache did not start successfully");
      }

      span.setAttribute(ATTR_DAEMON_PID, pid);

      const daemonLog = tailLog(this.daemonDir);

      try {
        log.debug(`about to post to localhost`);
        const res: Response<string> = await this.httpClient.post(
          `http://${this.hostAndPort}/api/workflow-finish`,
        );

        span.setAttribute(ATTR_STATUS_CODE, res.statusCode);

        log.debug(
          `Response from POST to /api/workflow-finish: (status: ${res.statusCode}, body: ${res.body})`,
        );

        if (res.statusCode !== 200) {
          throw new Error(
            `Failed to trigger workflow finish hook; expected status 200 but got (status: ${res.statusCode}, body: ${res.body})`,
          );
        }
      } finally {
        log.debug(`unwatching the daemon log`);
        daemonLog.unwatch();
      }

      log.debug(`killing daemon process ${pid}`);

      let sentSigterm = false;
      try {
        // Repeatedly signal 0 the daemon to test if it is up.
        // If it exits, kill will raise an exception which breaks us out of this control flow and skips the sigterm.
        // If magic-nix-cache doesn't exit in 30s, we SIGTERM it.
        for (let i = 0; i < 30 * 10; i++) {
          process.kill(pid, 0);
          await setTimeout(100);
        }

        sentSigterm = true;
        log.info(`Sending Magic Nix Cache a SIGTERM`);
        process.kill(pid, "SIGTERM");
      } catch {
        // Perfectly normal to get an exception here, because the process shut down.
      }

      this.setAttribute(ATTR_SENT_SIGTERM, sentSigterm);

      if (actionsCore.isDebug()) {
        log.info("Entire log:");
        const entireLog = readFileSync(path.join(this.daemonDir, "daemon.log"));
        log.info(entireLog.toString());
      }
    });
  }

  // Exit the workflow during the main phase. If strict mode is set, fail; if not, save the error
  // message to the workflow's state and exit successfully.
  private exitMain(msg: string): void {
    if (this.strictMode) {
      log.setFailed(msg);
    } else {
      actionsCore.saveState(STATE_ERROR_IN_MAIN, msg);
      process.exit(0);
    }
  }

  // If the main phase threw an error (not in strict mode), this will be a non-empty
  // string available in the post phase.
  private get errorInMain(): string | undefined {
    const state = actionsCore.getState(STATE_ERROR_IN_MAIN);
    return state !== "" ? state : undefined;
  }
}

function main(): void {
  new MagicNixCacheAction().execute();
}

main();
