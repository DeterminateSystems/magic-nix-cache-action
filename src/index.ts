import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { spawn, exec, SpawnOptions } from "node:child_process";
import { openSync, readFileSync } from "node:fs";
import { inspect, promisify } from "node:util";
import * as http from "http";

import * as core from "@actions/core";
import { Tail } from "tail";
import got from "got";
import { IdsToolbox } from "detsys-ts";
import * as platform from "./platform.js";

const ENV_CACHE_DAEMONDIR = "MAGIC_NIX_CACHE_DAEMONDIR";

const gotClient = got.extend({
  retry: {
    limit: 1,
    methods: ["POST", "GET", "PUT", "HEAD", "DELETE", "OPTIONS", "TRACE"],
  },
  hooks: {
    beforeRetry: [
      (error, retryCount) => {
        core.info(`Retrying after error ${error.code}, retry #: ${retryCount}`);
      },
    ],
  },
});

async function fetchAutoCacher(toolbox: IdsToolbox): Promise<string> {
  const closurePath = await toolbox.fetch();
  toolbox.recordEvent("load_closure");
  const { stdout } = await promisify(exec)(
    `cat "${closurePath}" | xz -d | nix-store --import`,
  );

  const paths = stdout.split(os.EOL);
  // Since the export is in reverse topologically sorted order, magic-nix-cache is always the penultimate entry in the list (the empty string left by split being the last).
  const last_path = paths.at(-2);
  return `${last_path}/bin/magic-nix-cache`;
}

function tailLog(daemonDir: string): Tail {
  const log = new Tail(path.join(daemonDir, "daemon.log"));
  core.debug(`tailing daemon.log...`);
  log.on("line", (line) => {
    core.info(line);
  });
  return log;
}

async function setUpAutoCache(toolbox: IdsToolbox): Promise<void> {
  const tmpdir = process.env["RUNNER_TEMP"] || os.tmpdir();
  const required_env = [
    "ACTIONS_CACHE_URL",
    "ACTIONS_RUNTIME_URL",
    "ACTIONS_RUNTIME_TOKEN",
  ];

  let anyMissing = false;
  for (const n of required_env) {
    if (!process.env.hasOwnProperty(n)) {
      anyMissing = true;
      core.warning(
        `Disabling automatic caching since required environment ${n} isn't available`,
      );
    }
  }

  if (anyMissing) {
    return;
  }

  core.debug(`GitHub Action Cache URL: ${process.env["ACTIONS_CACHE_URL"]}`);

  const daemonDir = await fs.mkdtemp(path.join(tmpdir, "magic-nix-cache-"));

  let daemonBin: string;
  if (core.getInput("source-binary")) {
    daemonBin = core.getInput("source-binary");
  } else {
    daemonBin = await fetchAutoCacher(toolbox);
  }

  let runEnv;
  if (core.isDebug()) {
    runEnv = {
      RUST_LOG: "trace,magic_nix_cache=debug,gha_cache=debug",
      RUST_BACKTRACE: "full",
      ...process.env,
    };
  } else {
    runEnv = process.env;
  }

  const notifyPort = core.getInput("startup-notification-port");

  const notifyPromise = new Promise<Promise<void>>((resolveListening) => {
    const promise = new Promise<void>(async (resolveQuit) => {
      const notifyServer = http.createServer((req, res) => {
        if (req.method === "POST" && req.url === "/") {
          core.debug(`Notify server shutting down.`);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end("{}");
          notifyServer.close(() => {
            resolveQuit();
          });
        }
      });

      notifyServer.listen(notifyPort, () => {
        core.debug(`Notify server running.`);
        resolveListening(promise);
      });
    });
  });

  // Start tailing the daemon log.
  const outputPath = `${daemonDir}/daemon.log`;
  const output = openSync(outputPath, "a");
  const log = tailLog(daemonDir);
  const netrc = await netrcPath();
  const nixConfPath = `${process.env["HOME"]}/.config/nix/nix.conf`;

  const daemonCliFlags: string[] = [
    "--startup-notification-url",
    `http://127.0.0.1:${notifyPort}`,
    "--listen",
    core.getInput("listen"),
    "--upstream",
    core.getInput("upstream-cache"),
    "--diagnostic-endpoint",
    core.getInput("diagnostic-endpoint"),
    "--nix-conf",
    nixConfPath,
  ]
    .concat(
      core.getBooleanInput("use-flakehub")
        ? [
            "--use-flakehub",
            "--flakehub-cache-server",
            core.getInput("flakehub-cache-server"),
            "--flakehub-api-server",
            core.getInput("flakehub-api-server"),
            "--flakehub-api-server-netrc",
            netrc,
            "--flakehub-flake-name",
            core.getInput("flakehub-flake-name"),
          ]
        : [],
    )
    .concat(core.getBooleanInput("use-gha-cache") ? ["--use-gha-cache"] : []);

  const opts: SpawnOptions = {
    stdio: ["ignore", output, output],
    env: runEnv,
    detached: true,
  };

  // Display the final command for debugging purposes
  core.debug("Full daemon start command:");
  core.debug(`${daemonBin} ${daemonCliFlags.join(" ")}`);

  // Start the server. Once it is ready, it will notify us via the notification server.
  const daemon = spawn(daemonBin, daemonCliFlags, opts);

  const pidFile = path.join(daemonDir, "daemon.pid");
  await fs.writeFile(pidFile, `${daemon.pid}`);

  core.info("Waiting for magic-nix-cache to start...");

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

  core.info("Launched Magic Nix Cache");
  core.exportVariable(ENV_CACHE_DAEMONDIR, daemonDir);

  log.unwatch();
}

async function notifyAutoCache(): Promise<void> {
  const daemonDir = process.env[ENV_CACHE_DAEMONDIR];

  if (!daemonDir) {
    return;
  }

  try {
    core.debug(`Indicating workflow start`);
    const res: Response = await gotClient
      .post(`http://${core.getInput("listen")}/api/workflow-start`)
      .json();
    core.debug(`back from post: ${res}`);
  } catch (e) {
    core.info(`Error marking the workflow as started:`);
    core.info(inspect(e));
    core.info(`Magic Nix Cache may not be running for this workflow.`);
  }
}

async function netrcPath(): Promise<string> {
  const expectedNetrcPath = path.join(
    process.env["RUNNER_TEMP"] || os.tmpdir(),
    "determinate-nix-installer-netrc",
  );
  try {
    await fs.access(expectedNetrcPath);
    return expectedNetrcPath;
  } catch {
    // `nix-installer` was not used, the user may be registered with FlakeHub though.
    const destinedNetrcPath = path.join(
      process.env["RUNNER_TEMP"] || os.tmpdir(),
      "magic-nix-cache-netrc",
    );
    try {
      await flakehub_login(destinedNetrcPath);
    } catch (e) {
      core.info("FlakeHub cache disabled.");
      core.debug(`Error while logging into FlakeHub: ${e}`);
    }
    return destinedNetrcPath;
  }
}

async function flakehub_login(netrc: string): Promise<void> {
  const jwt = await core.getIDToken("api.flakehub.com");

  await fs.writeFile(
    netrc,
    [
      `machine api.flakehub.com login flakehub password ${jwt}`,
      `machine flakehub.com login flakehub password ${jwt}`,
      `machine cache.flakehub.com login flakehub password ${jwt}`,
    ].join("\n"),
  );

  core.info("Logged in to FlakeHub.");
}

async function tearDownAutoCache(): Promise<void> {
  const daemonDir = process.env[ENV_CACHE_DAEMONDIR];

  if (!daemonDir) {
    core.debug("magic-nix-cache not started - Skipping");
    return;
  }

  const pidFile = path.join(daemonDir, "daemon.pid");
  const pid = parseInt(await fs.readFile(pidFile, { encoding: "ascii" }));
  core.debug(`found daemon pid: ${pid}`);
  if (!pid) {
    throw new Error("magic-nix-cache did not start successfully");
  }

  const log = tailLog(daemonDir);

  try {
    core.debug(`about to post to localhost`);
    const res: Response = await gotClient
      .post(`http://${core.getInput("listen")}/api/workflow-finish`)
      .json();
    core.debug(`back from post: ${res}`);
  } finally {
    core.debug(`unwatching the daemon log`);
    log.unwatch();
  }

  core.debug(`killing`);
  try {
    process.kill(pid, "SIGTERM");
  } catch (e) {
    if (typeof e === "object" && e && "code" in e && e.code !== "ESRCH") {
      throw e;
    }
  } finally {
    if (core.isDebug()) {
      core.info("Entire log:");
      const entireLog = readFileSync(path.join(daemonDir, "daemon.log"));
      core.info(entireLog.toString());
    }
  }
}

const idslib = new IdsToolbox({
  name: "magic-nix-cache",
  fetchStyle: "gh-env-style",
  idsProjectName: "magic-nix-cache-closure",
  requireNix: "warn",
});

idslib.onMain(async () => {
  // eslint-disable-next-line no-console
  console.log(platform);

  // eslint-disable-next-line no-console
  console.log(platform.getDetails());
  await setUpAutoCache(idslib);
  await notifyAutoCache();
});
idslib.onPost(async () => {
  await tearDownAutoCache();
});

idslib.execute();
