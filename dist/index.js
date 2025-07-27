// src/helpers.ts
import * as actionsCore from "@actions/core";
import * as fs from "fs/promises";
import * as os from "os";
import path from "path";
import { Tail } from "tail";
function getTrinaryInput(name) {
  const trueValue = ["true", "True", "TRUE", "enabled"];
  const falseValue = ["false", "False", "FALSE", "disabled"];
  const noPreferenceValue = ["", "null", "no-preference"];
  const val = actionsCore.getInput(name);
  if (trueValue.includes(val)) {
    return "enabled";
  }
  if (falseValue.includes(val)) {
    return "disabled";
  }
  if (noPreferenceValue.includes(val)) {
    return "no-preference";
  }
  const possibleValues = trueValue.concat(falseValue).concat(noPreferenceValue).join(" | ");
  throw new TypeError(
    `Input ${name} does not look like a trinary, which requires one of:
${possibleValues}`
  );
}
function tailLog(daemonDir) {
  const log = new Tail(path.join(daemonDir, "daemon.log"));
  actionsCore.debug(`tailing daemon.log...`);
  log.on("line", (line) => {
    actionsCore.info(line);
  });
  return log;
}
async function netrcPath() {
  const expectedNetrcPath = path.join(
    process.env["RUNNER_TEMP"] ?? os.tmpdir(),
    "determinate-nix-installer-netrc"
  );
  try {
    await fs.access(expectedNetrcPath);
    return expectedNetrcPath;
  } catch {
    const destinedNetrcPath = path.join(
      process.env["RUNNER_TEMP"] ?? os.tmpdir(),
      "magic-nix-cache-netrc"
    );
    try {
      await flakeHubLogin(destinedNetrcPath);
    } catch (e) {
      actionsCore.info(
        "FlakeHub Cache is disabled due to missing or invalid token"
      );
      actionsCore.info(
        `If you're signed up for FlakeHub Cache, make sure that your Actions config has a \`permissions\` block with \`id-token\` set to "write" and \`contents\` set to "read"`
      );
      actionsCore.debug(`Error while logging into FlakeHub: ${e}`);
    }
    return destinedNetrcPath;
  }
}
async function flakeHubLogin(netrc) {
  const jwt = await actionsCore.getIDToken("api.flakehub.com");
  await fs.writeFile(
    netrc,
    [
      `machine api.flakehub.com login flakehub password ${jwt}`,
      `machine flakehub.com login flakehub password ${jwt}`,
      `machine cache.flakehub.com login flakehub password ${jwt}`
    ].join("\n")
  );
  actionsCore.info("Logged in to FlakeHub.");
}

// src/index.ts
import * as actionsCore2 from "@actions/core";
import * as actionsGithub from "@actions/github";
import { DetSysAction, inputs, stringifyError } from "detsys-ts";
import got from "got";
import * as http from "http";
import { spawn } from "child_process";
import { mkdirSync, openSync, readFileSync } from "fs";
import * as fs2 from "fs/promises";
import * as path2 from "path";
import { setTimeout } from "timers/promises";
var ENV_DAEMON_DIR = "MAGIC_NIX_CACHE_DAEMONDIR";
var FACT_ENV_VARS_PRESENT = "required_env_vars_present";
var FACT_SENT_SIGTERM = "sent_sigterm";
var FACT_DIFF_STORE_ENABLED = "diff_store";
var FACT_ALREADY_RUNNING = "noop_mode";
var STATE_DAEMONDIR = "MAGIC_NIX_CACHE_DAEMONDIR";
var STATE_ERROR_IN_MAIN = "ERROR_IN_MAIN";
var STATE_STARTED = "MAGIC_NIX_CACHE_STARTED";
var STARTED_HINT = "true";
var TEXT_ALREADY_RUNNING = "Magic Nix Cache is already running, this workflow job is in noop mode. Is the Magic Nix Cache in the workflow twice?";
var TEXT_TRUST_UNTRUSTED = "The Nix daemon does not consider the user running this workflow to be trusted. Magic Nix Cache is disabled.";
var TEXT_TRUST_UNKNOWN = "The Nix daemon may not consider the user running this workflow to be trusted. Magic Nix Cache may not start correctly.";
var MagicNixCacheAction = class extends DetSysAction {
  constructor() {
    super({
      name: "magic-nix-cache",
      fetchStyle: "gh-env-style",
      idsProjectName: "magic-nix-cache-closure",
      requireNix: "warn",
      diagnosticsSuffix: "perf"
    });
    this.hostAndPort = inputs.getString("listen");
    this.diffStore = inputs.getBool("diff-store");
    this.addFact(FACT_DIFF_STORE_ENABLED, this.diffStore);
    this.httpClient = got.extend({
      retry: {
        limit: 1,
        methods: ["POST", "GET", "PUT", "HEAD", "DELETE", "OPTIONS", "TRACE"]
      },
      hooks: {
        beforeRetry: [
          (error, retryCount) => {
            actionsCore2.info(
              `Retrying after error ${error.code}, retry #: ${retryCount}`
            );
          }
        ]
      }
    });
    this.daemonStarted = actionsCore2.getState(STATE_STARTED) === STARTED_HINT;
    if (actionsCore2.getState(STATE_DAEMONDIR) !== "") {
      this.daemonDir = actionsCore2.getState(STATE_DAEMONDIR);
    } else {
      this.daemonDir = this.getTemporaryName();
      mkdirSync(this.daemonDir);
      actionsCore2.saveState(STATE_DAEMONDIR, this.daemonDir);
    }
    if (process.env[ENV_DAEMON_DIR] === void 0) {
      this.alreadyRunning = false;
      actionsCore2.exportVariable(ENV_DAEMON_DIR, this.daemonDir);
    } else {
      this.alreadyRunning = process.env[ENV_DAEMON_DIR] !== this.daemonDir;
    }
    this.addFact(FACT_ALREADY_RUNNING, this.alreadyRunning);
    this.stapleFile("daemon.log", path2.join(this.daemonDir, "daemon.log"));
  }
  async main() {
    if (this.alreadyRunning) {
      actionsCore2.warning(TEXT_ALREADY_RUNNING);
      return;
    }
    if (this.nixStoreTrust === "untrusted") {
      actionsCore2.warning(TEXT_TRUST_UNTRUSTED);
      return;
    } else if (this.nixStoreTrust === "unknown") {
      actionsCore2.info(TEXT_TRUST_UNKNOWN);
    }
    await this.setUpAutoCache();
    await this.notifyAutoCache();
  }
  async post() {
    if (!this.strictMode && this.errorInMain) {
      actionsCore2.warning(
        `skipping post phase due to error in main phase: ${this.errorInMain}`
      );
      return;
    }
    if (this.alreadyRunning) {
      actionsCore2.debug(TEXT_ALREADY_RUNNING);
      return;
    }
    if (this.nixStoreTrust === "untrusted") {
      actionsCore2.debug(TEXT_TRUST_UNTRUSTED);
      return;
    } else if (this.nixStoreTrust === "unknown") {
      actionsCore2.debug(TEXT_TRUST_UNKNOWN);
    }
    await this.tearDownAutoCache();
  }
  async setUpAutoCache() {
    const requiredEnv = [
      "ACTIONS_CACHE_URL",
      "ACTIONS_RUNTIME_URL",
      "ACTIONS_RUNTIME_TOKEN"
    ];
    let anyMissing = false;
    for (const n of requiredEnv) {
      const override = `OVERRIDE_${n}`;
      const overrideDesc = Object.getOwnPropertyDescriptor(process.env, override);
      if (overrideDesc) {
        actionsCore2.debug(`Overriding env ${n}=${process.env[n]} with ${override}=${process.env[override]}`);
        Object.defineProperty(process.env, n, overrideDesc);
      }
      if (!process.env.hasOwnProperty(n)) {
        anyMissing = true;
        actionsCore2.warning(
          `Disabling automatic caching since required environment ${n} isn't available`
        );
      }
    }
    this.addFact(FACT_ENV_VARS_PRESENT, !anyMissing);
    if (anyMissing) {
      return;
    }
    if (this.daemonStarted) {
      actionsCore2.debug("Already started.");
      return;
    }
    actionsCore2.debug(
      `GitHub Action Cache URL: ${process.env["ACTIONS_CACHE_URL"]}`
    );
    const daemonBin = await this.unpackClosure("magic-nix-cache");
    const extraEnv = {
      GITHUB_CONTEXT: JSON.stringify(actionsGithub.context)
    };
    let runEnv = {};
    if (actionsCore2.isDebug()) {
      runEnv = {
        RUST_LOG: "debug,magic_nix_cache=trace,gha_cache=trace",
        RUST_BACKTRACE: "full",
        ...process.env,
        ...extraEnv
      };
    } else {
      runEnv = {
        ...process.env,
        ...extraEnv
      };
    }
    const notifyPort = inputs.getString("startup-notification-port");
    const notifyPromise = new Promise((resolveListening) => {
      const promise = new Promise(async (resolveQuit) => {
        const notifyServer = http.createServer((req, res) => {
          if (req.method === "POST" && req.url === "/") {
            actionsCore2.debug(`Notify server shutting down.`);
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end("{}");
            notifyServer.close(() => {
              resolveQuit();
            });
          }
        });
        notifyServer.listen(notifyPort, () => {
          actionsCore2.debug(`Notify server running.`);
          resolveListening(promise);
        });
      });
    });
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
    const daemonCliFlags = [
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
      useFlakeHub
    ].concat(this.diffStore ? ["--diff-store"] : []).concat(
      useFlakeHub !== "disabled" ? [
        "--flakehub-cache-server",
        flakeHubCacheServer,
        "--flakehub-api-server",
        flakeHubApiServer,
        "--flakehub-api-server-netrc",
        netrc,
        "--flakehub-flake-name",
        flakeHubFlakeName
      ] : []
    );
    const opts = {
      stdio: ["ignore", output, output],
      env: runEnv,
      detached: true
    };
    actionsCore2.debug("Full daemon start command:");
    actionsCore2.debug(`${daemonBin} ${daemonCliFlags.join(" ")}`);
    const daemon = spawn(daemonBin, daemonCliFlags, opts);
    this.daemonStarted = true;
    actionsCore2.saveState(STATE_STARTED, STARTED_HINT);
    const pidFile = path2.join(this.daemonDir, "daemon.pid");
    await fs2.writeFile(pidFile, `${daemon.pid}`);
    actionsCore2.info("Waiting for magic-nix-cache to start...");
    await new Promise((resolve) => {
      notifyPromise.then((_value) => {
        resolve();
      }).catch((e) => {
        this.exitMain(`Error in notifyPromise: ${stringifyError(e)}`);
      });
      daemon.on("exit", async (code, signal) => {
        let msg;
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
    actionsCore2.info("Launched Magic Nix Cache");
    log.unwatch();
  }
  async notifyAutoCache() {
    if (!this.daemonStarted) {
      actionsCore2.debug("magic-nix-cache not started - Skipping");
      return;
    }
    try {
      actionsCore2.debug(`Indicating workflow start`);
      const res = await this.httpClient.post(
        `http://${this.hostAndPort}/api/workflow-start`
      );
      actionsCore2.debug(
        `Response from POST to /api/workflow-start: (status: ${res.statusCode}, body: ${res.body})`
      );
      if (res.statusCode !== 200) {
        throw new Error(
          `Failed to trigger workflow start hook; expected status 200 but got (status: ${res.statusCode}, body: ${res.body})`
        );
      }
      actionsCore2.debug(`back from post: ${res.body}`);
    } catch (e) {
      this.exitMain(`Error starting the Magic Nix Cache: ${stringifyError(e)}`);
    }
  }
  async tearDownAutoCache() {
    if (!this.daemonStarted) {
      actionsCore2.debug("magic-nix-cache not started - Skipping");
      return;
    }
    const pidFile = path2.join(this.daemonDir, "daemon.pid");
    const pid = parseInt(await fs2.readFile(pidFile, { encoding: "ascii" }));
    actionsCore2.debug(`found daemon pid: ${pid}`);
    if (!pid) {
      throw new Error("magic-nix-cache did not start successfully");
    }
    const log = tailLog(this.daemonDir);
    try {
      actionsCore2.debug(`about to post to localhost`);
      const res = await this.httpClient.post(
        `http://${this.hostAndPort}/api/workflow-finish`
      );
      actionsCore2.debug(
        `Response from POST to /api/workflow-finish: (status: ${res.statusCode}, body: ${res.body})`
      );
      if (res.statusCode !== 200) {
        throw new Error(
          `Failed to trigger workflow finish hook; expected status 200 but got (status: ${res.statusCode}, body: ${res.body})`
        );
      }
    } finally {
      actionsCore2.debug(`unwatching the daemon log`);
      log.unwatch();
    }
    actionsCore2.debug(`killing daemon process ${pid}`);
    try {
      for (let i = 0; i < 30 * 10; i++) {
        process.kill(pid, 0);
        await setTimeout(100);
      }
      this.addFact(FACT_SENT_SIGTERM, true);
      actionsCore2.info(`Sending Magic Nix Cache a SIGTERM`);
      process.kill(pid, "SIGTERM");
    } catch {
    }
    if (actionsCore2.isDebug()) {
      actionsCore2.info("Entire log:");
      const entireLog = readFileSync(path2.join(this.daemonDir, "daemon.log"));
      actionsCore2.info(entireLog.toString());
    }
  }
  // Exit the workflow during the main phase. If strict mode is set, fail; if not, save the error
  // message to the workflow's state and exit successfully.
  exitMain(msg) {
    if (this.strictMode) {
      actionsCore2.setFailed(msg);
    } else {
      actionsCore2.saveState(STATE_ERROR_IN_MAIN, msg);
      process.exit(0);
    }
  }
  // If the main phase threw an error (not in strict mode), this will be a non-empty
  // string available in the post phase.
  get errorInMain() {
    const state = actionsCore2.getState(STATE_ERROR_IN_MAIN);
    return state !== "" ? state : void 0;
  }
};
function main() {
  new MagicNixCacheAction().execute();
}
main();
//# sourceMappingURL=index.js.map