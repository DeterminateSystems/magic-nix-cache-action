import * as actionsCore from "@actions/core";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import path from "node:path";
import { Tail } from "tail";

export function tailLog(daemonDir: string): Tail {
  const log = new Tail(path.join(daemonDir, "daemon.log"));
  actionsCore.debug(`tailing daemon.log...`);
  log.on("line", (line) => {
    actionsCore.info(line);
  });
  return log;
}

export async function netrcPath(): Promise<string> {
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
      await flakeHubLogin(destinedNetrcPath);
    } catch (e) {
      actionsCore.info("FlakeHub cache disabled.");
      actionsCore.debug(`Error while logging into FlakeHub: ${e}`);
    }
    return destinedNetrcPath;
  }
}

async function flakeHubLogin(netrc: string): Promise<void> {
  const jwt = await actionsCore.getIDToken("api.flakehub.com");

  await fs.writeFile(
    netrc,
    [
      `machine api.flakehub.com login flakehub password ${jwt}`,
      `machine flakehub.com login flakehub password ${jwt}`,
      `machine cache.flakehub.com login flakehub password ${jwt}`,
    ].join("\n"),
  );

  actionsCore.info("Logged in to FlakeHub.");
}
