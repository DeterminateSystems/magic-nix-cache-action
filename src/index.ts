import { netrcPath, tailLog } from "./helpers.js";
import * as actionsCore from "@actions/core";
import { IdsToolbox, inputs } from "detsys-ts";
import got, { Got, Response } from "got";
import * as http from "http";
import { SpawnOptions, exec, spawn } from "node:child_process";
import { mkdirSync, openSync, readFileSync } from "node:fs";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { inspect, promisify } from "node:util";

// The ENV_DAEMON_DIR is intended to determine if we "own" the daemon or not,
// in the case that a user has put the magic nix cache into their workflow
// twice.
const ENV_DAEMON_DIR = "MAGIC_NIX_CACHE_DAEMONDIR";

const STATE_DAEMONDIR = "MAGIC_NIX_CACHE_DAEMONDIR";
const STATE_STARTED = "MAGIC_NIX_CACHE_STARTED";
const STARTED_HINT = "true";

const TEXT_NOOP =
  "Magic Nix Cache is already running, this workflow job is in noop mode. Is the Magic Nix Cache in the workflow twice?";
const TEXT_TRUST_UNTRUSTED =
  "The Nix daemon does not consider the user running this workflow to be trusted. Magic Nix Cache is disabled.";
const TEXT_TRUST_UNKNOWN =
  "The Nix daemon may not consider the user running this workflow to be trusted. Magic Nix Cache may not start correctly.";

class MagicNixCacheAction {
  idslib: IdsToolbox;
  private strictMode: boolean;
  private client: Got;

  noopMode: boolean;
  private daemonDir: string;
  private daemonStarted: boolean;

  constructor() {
    this.idslib = new IdsToolbox({
      name: "magic-nix-cache",
      fetchStyle: "gh-env-style",
      idsProjectName: "magic-nix-cache-closure",
      requireNix: "warn",
    });

    this.strictMode = inputs.getBool("strict-mode");

    this.client = got.extend({
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
      this.daemonDir = this.idslib.getTemporaryName();
      mkdirSync(this.daemonDir);
      actionsCore.saveState(STATE_DAEMONDIR, this.daemonDir);
    }

    if (process.env[ENV_DAEMON_DIR] === undefined) {
      this.noopMode = false;
      actionsCore.exportVariable(ENV_DAEMON_DIR, this.daemonDir);
    } else {
      this.noopMode = process.env[ENV_DAEMON_DIR] !== this.daemonDir;
    }
    this.idslib.addFact("noop_mode", this.noopMode);

    this.idslib.stapleFile(
      "daemon.log",
      path.join(this.daemonDir, "daemon.log"),
    );
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

    this.idslib.addFact("authenticated_env", !anyMissing);
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

    const sourceBinary = inputs.getStringOrNull("source-binary");
    const daemonBin =
      sourceBinary !== null ? sourceBinary : await this.fetchAutoCacher();

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

    const hostAndPort = inputs.getString("listen");
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
      hostAndPort,
      "--upstream",
      upstreamCache,
      "--diagnostic-endpoint",
      diagnosticEndpoint,
      "--nix-conf",
      nixConfPath,
    ]
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
        .catch((err) => {
          const msg = `error in notifyPromise: ${err}`;
          reject(new Error(msg));
          this.failInStrictMode(msg);
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
        this.failInStrictMode(msg);
      });
    });

    daemon.unref();

    actionsCore.info("Launched Magic Nix Cache");

    log.unwatch();
  }

  private async fetchAutoCacher(): Promise<string> {
    const closurePath = await this.idslib.fetch();
    this.idslib.recordEvent("load_closure");
    const { stdout } = await promisify(exec)(
      `cat "${closurePath}" | xz -d | nix-store --import`,
    );

    const paths = stdout.split(os.EOL);
    // Since the export is in reverse topologically sorted order, magic-nix-cache is always the penultimate entry in the list (the empty string left by split being the last).
    const lastPath = paths.at(-2);
    return `${lastPath}/bin/magic-nix-cache`;
  }

  async notifyAutoCache(): Promise<void> {
    if (!this.daemonStarted) {
      actionsCore.debug("magic-nix-cache not started - Skipping");
      return;
    }

    try {
      actionsCore.debug(`Indicating workflow start`);
      const hostAndPort = inputs.getString("listen");
      const res: Response<string> = await this.client.post(
        `http://${hostAndPort}/api/workflow-start`,
      );

      if (res.statusCode !== 200) {
        this.failInStrictMode(
          `Failed to trigger workflow start hook; expected status 200 but got ${res.statusCode}`,
        );
      }

      actionsCore.debug(`back from post: ${res.body}`);
    } catch (e) {
      actionsCore.info(`Error marking the workflow as started:`);
      actionsCore.info(inspect(e));
      actionsCore.info(`Magic Nix Cache may not be running for this workflow.`);

      this.failInStrictMode(`Magic Nix Cache failed to start: ${inspect(e)}`);
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
      const msg = "magic-nix-cache did not start successfully";
      this.failInStrictMode(msg);
      throw new Error(msg);
    }

    const log = tailLog(this.daemonDir);

    try {
      actionsCore.debug(`about to post to localhost`);
      const hostAndPort = inputs.getString("listen");
      const res: Response<string> = await this.client.post(
        `http://${hostAndPort}/api/workflow-finish`,
      );

      if (res.statusCode !== 200) {
        this.failInStrictMode(
          `Failed to trigger workflow finish hook; expected status 200 but got ${res.statusCode}`,
        );
      }

      actionsCore.debug(`back from post: ${res.body}`);
    } finally {
      actionsCore.debug(`unwatching the daemon log`);
      log.unwatch();
    }

    actionsCore.debug(`killing`);
    try {
      process.kill(pid, "SIGTERM");
    } catch (e) {
      if (typeof e === "object" && e && "code" in e && e.code !== "ESRCH") {
        this.failInStrictMode(e.toString());
        throw e;
      }
    } finally {
      if (actionsCore.isDebug()) {
        actionsCore.info("Entire log:");
        const entireLog = readFileSync(path.join(this.daemonDir, "daemon.log"));
        actionsCore.info(entireLog.toString());
      }
    }
  }

  private failInStrictMode(msg: string): void {
    if (this.strictMode) {
      actionsCore.setFailed(`strict mode error: ${msg}`);
    }
  }
}

function main(): void {
  const cacheAction = new MagicNixCacheAction();

  cacheAction.idslib.onMain(async () => {
    if (cacheAction.noopMode) {
      actionsCore.warning(TEXT_NOOP);
      return;
    }

    if (cacheAction.idslib.nixStoreTrust === "untrusted") {
      actionsCore.warning(TEXT_TRUST_UNTRUSTED);
      return;
    } else if (cacheAction.idslib.nixStoreTrust === "unknown") {
      actionsCore.info(TEXT_TRUST_UNKNOWN);
    }

    await cacheAction.setUpAutoCache();
    await cacheAction.notifyAutoCache();
  });
  cacheAction.idslib.onPost(async () => {
    if (cacheAction.noopMode) {
      actionsCore.debug(TEXT_NOOP);
      return;
    }

    if (cacheAction.idslib.nixStoreTrust === "untrusted") {
      actionsCore.debug(TEXT_TRUST_UNTRUSTED);
      return;
    } else if (cacheAction.idslib.nixStoreTrust === "unknown") {
      actionsCore.debug(TEXT_TRUST_UNKNOWN);
    }

    await cacheAction.tearDownAutoCache();
  });

  cacheAction.idslib.execute();
}

main();
