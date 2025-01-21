import { getTrinaryInput, netrcPath, tailLog } from "./helpers.js";
import { warnOnMnc } from "./mnc-warn.js";
import * as actionsCore from "@actions/core";
import { DetSysAction, inputs, stringifyError } from "detsys-ts";
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

const FACT_ENV_VARS_PRESENT = "required_env_vars_present";
const FACT_SENT_SIGTERM = "sent_sigterm";
const FACT_DIFF_STORE_ENABLED = "diff_store";
const FACT_ALREADY_RUNNING = "noop_mode";

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
      this.alreadyRunning = false;
      actionsCore.exportVariable(ENV_DAEMON_DIR, this.daemonDir);
    } else {
      this.alreadyRunning = process.env[ENV_DAEMON_DIR] !== this.daemonDir;
    }
    this.addFact(FACT_ALREADY_RUNNING, this.alreadyRunning);

    this.stapleFile("daemon.log", path.join(this.daemonDir, "daemon.log"));
  }

  async main(): Promise<void> {
    if (this.alreadyRunning) {
      actionsCore.warning(TEXT_ALREADY_RUNNING);
      return;
    }

    if (this.getFeature("warn-magic-nix-cache-eol")?.variant === true) {
      await warnOnMnc();
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
    // If strict mode is off and there was an error in main, such as the daemon not starting,
    // then the post phase is skipped with a warning.
    if (!this.strictMode && this.errorInMain) {
      actionsCore.warning(
        `skipping post phase due to error in main phase: ${this.errorInMain}`,
      );
      return;
    }

    if (this.alreadyRunning) {
      actionsCore.debug(TEXT_ALREADY_RUNNING);
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
        RUST_LOG: "debug,magic_nix_cache=trace,gha_cache=trace",
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
    const useFlakeHub = getTrinaryInput("use-flakehub");
    const flakeHubCacheServer = inputs.getString("flakehub-cache-server");
    const flakeHubApiServer = inputs.getString("flakehub-api-server");
    const flakeHubFlakeName = inputs.getString("flakehub-flake-name");
    const useGhaCache = getTrinaryInput("use-gha-cache");

    const daemonCliFlags: string[] = [
      "--startup-notification-url",
      `http://127.0.0.1:${notifyPort}`,
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
    actionsCore.debug("Full daemon start command:");
    actionsCore.debug(`${daemonBin} ${daemonCliFlags.join(" ")}`);

    // Start the server. Once it is ready, it will notify us via the notification server.
    const daemon = spawn(daemonBin, daemonCliFlags, opts);

    this.daemonStarted = true;
    actionsCore.saveState(STATE_STARTED, STARTED_HINT);

    const pidFile = path.join(this.daemonDir, "daemon.pid");
    await fs.writeFile(pidFile, `${daemon.pid}`);

    actionsCore.info("Waiting for magic-nix-cache to start...");

    await new Promise<void>((resolve) => {
      notifyPromise
        // eslint-disable-next-line github/no-then
        .then((_value) => {
          resolve();
        })
        // eslint-disable-next-line github/no-then
        .catch((e: unknown) => {
          this.exitMain(`Error in notifyPromise: ${stringifyError(e)}`);
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

        this.exitMain(msg);
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
      this.exitMain(`Error starting the Magic Nix Cache: ${stringifyError(e)}`);
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

    actionsCore.debug(`killing daemon process ${pid}`);

    try {
      // Repeatedly signal 0 the daemon to test if it is up.
      // If it exits, kill will raise an exception which breaks us out of this control flow and skips the sigterm.
      // If magic-nix-cache doesn't exit in 30s, we SIGTERM it.
      for (let i = 0; i < 30 * 10; i++) {
        process.kill(pid, 0);
        await setTimeout(100);
      }

      this.addFact(FACT_SENT_SIGTERM, true);
      actionsCore.info(`Sending Magic Nix Cache a SIGTERM`);
      process.kill(pid, "SIGTERM");
    } catch {
      // Perfectly normal to get an exception here, because the process shut down.
    }

    if (actionsCore.isDebug()) {
      actionsCore.info("Entire log:");
      const entireLog = readFileSync(path.join(this.daemonDir, "daemon.log"));
      actionsCore.info(entireLog.toString());
    }
  }

  // Exit the workflow during the main phase. If strict mode is set, fail; if not, save the error
  // message to the workflow's state and exit successfully.
  private exitMain(msg: string): void {
    if (this.strictMode) {
      actionsCore.setFailed(msg);
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
