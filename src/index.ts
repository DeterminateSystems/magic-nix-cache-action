import { netrcPath, tailLog } from "./helpers.js";
import * as actionsCore from "@actions/core";
import { IdsToolbox, inputs } from "detsys-ts";
import { mkdir, stat } from "fs/promises";
import got, { Got } from "got";
import * as http from "http";
import { SpawnOptions, exec, spawn } from "node:child_process";
import { openSync, readFileSync } from "node:fs";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { inspect, promisify } from "node:util";

const ENV_CACHE_DAEMONDIR = "MAGIC_NIX_CACHE_DAEMONDIR";

class MagicNixCacheAction {
  idslib: IdsToolbox;
  private client: Got;

  private daemonDir?: string;
  private unsafeDaemonDir: string;

  constructor() {
    this.idslib = new IdsToolbox({
      name: "magic-nix-cache",
      fetchStyle: "gh-env-style",
      idsProjectName: "magic-nix-cache-closure",
      requireNix: "warn",
    });

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

    if (process.env[ENV_CACHE_DAEMONDIR]) {
      this.unsafeDaemonDir = process.env[ENV_CACHE_DAEMONDIR];
    } else {
      this.unsafeDaemonDir = this.idslib.getTemporaryName();
      actionsCore.exportVariable(ENV_CACHE_DAEMONDIR, this.unsafeDaemonDir);
    }
  }

  async getDaemonDir(): Promise<string> {
    if (this.daemonDir === undefined) {
      await mkdir(this.unsafeDaemonDir, { recursive: true });
      this.daemonDir = this.unsafeDaemonDir;
      return this.unsafeDaemonDir;
    } else {
      return this.daemonDir;
    }
  }

  async daemonDirExists(): Promise<boolean> {
    const statRes = await stat(this.unsafeDaemonDir);
    return statRes.isDirectory();
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

    if (anyMissing) {
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
    const daemonDir = await this.getDaemonDir();
    const outputPath = `${daemonDir}/daemon.log`;
    const output = openSync(outputPath, "a");
    const log = tailLog(daemonDir);
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

    const pidFile = path.join(daemonDir, "daemon.pid");
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
          reject(new Error(`error in notifyPromise: ${err}`));
        });
      daemon.on("exit", async (code, signal) => {
        if (signal) {
          reject(new Error(`Daemon was killed by signal ${signal}`));
        } else if (code) {
          reject(new Error(`Daemon exited with code ${code}`));
        } else {
          reject(new Error(`Daemon unexpectedly exited`));
        }
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
    if (!await this.daemonDirExists()) {
      actionsCore.debug("magic-nix-cache not started - Skipping");
      return;
    }

    try {
      actionsCore.debug(`Indicating workflow start`);
      const hostAndPort = inputs.getString("listen");
      const res: Response = await this.client
        .post(`http://${hostAndPort}/api/workflow-start`)
        .json();
      actionsCore.debug(`back from post: ${res}`);
    } catch (e) {
      actionsCore.info(`Error marking the workflow as started:`);
      actionsCore.info(inspect(e));
      actionsCore.info(`Magic Nix Cache may not be running for this workflow.`);
    }
  }

  async tearDownAutoCache(): Promise<void> {
    if (!await this.daemonDirExists()) {
      actionsCore.debug("magic-nix-cache not started - Skipping");
      return;
    }
    const daemonDir = await this.getDaemonDir();

    const pidFile = path.join(daemonDir, "daemon.pid");
    const pid = parseInt(await fs.readFile(pidFile, { encoding: "ascii" }));
    actionsCore.debug(`found daemon pid: ${pid}`);
    if (!pid) {
      throw new Error("magic-nix-cache did not start successfully");
    }

    const log = tailLog(daemonDir);

    try {
      actionsCore.debug(`about to post to localhost`);
      const hostAndPort = inputs.getString("listen");
      const res: Response = await this.client
        .post(`http://${hostAndPort}/api/workflow-finish`)
        .json();
      actionsCore.debug(`back from post: ${res}`);
    } finally {
      actionsCore.debug(`unwatching the daemon log`);
      log.unwatch();
    }

    actionsCore.debug(`killing`);
    try {
      process.kill(pid, "SIGTERM");
    } catch (e) {
      if (typeof e === "object" && e && "code" in e && e.code !== "ESRCH") {
        throw e;
      }
    } finally {
      if (actionsCore.isDebug()) {
        actionsCore.info("Entire log:");
        const entireLog = readFileSync(path.join(daemonDir, "daemon.log"));
        actionsCore.info(entireLog.toString());
      }
    }
  }
}

function main(): void {
  const cacheAction = new MagicNixCacheAction();

  cacheAction.idslib.onMain(async () => {
    await cacheAction.setUpAutoCache();
    await cacheAction.notifyAutoCache();
  });
  cacheAction.idslib.onPost(async () => {
    await cacheAction.tearDownAutoCache();
  });

  cacheAction.idslib.execute();
}

main();
