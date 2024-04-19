// MIT, lifted from https://github.com/actions/toolkit/blob/5a736647a123ecf8582376bdaee833fbae5b3847/packages/core/src/platform.ts
// since it isn't in @actions/core 1.10.1 which is their current release as 2024-04-19

import os from "os";
import * as exec from "@actions/exec";
import * as core from "@actions/core";
import { releaseInfo } from "linux-release-info";

const getWindowsInfo = async (): Promise<{ name: string; version: string }> => {
  const { stdout: version } = await exec.getExecOutput(
    'powershell -command "(Get-CimInstance -ClassName Win32_OperatingSystem).Version"',
    undefined,
    {
      silent: true,
    },
  );

  const { stdout: name } = await exec.getExecOutput(
    'powershell -command "(Get-CimInstance -ClassName Win32_OperatingSystem).Caption"',
    undefined,
    {
      silent: true,
    },
  );

  return {
    name: name.trim(),
    version: version.trim(),
  };
};

const getMacOsInfo = async (): Promise<{
  name: string;
  version: string;
}> => {
  const { stdout } = await exec.getExecOutput("sw_vers", undefined, {
    silent: true,
  });

  const version = stdout.match(/ProductVersion:\s*(.+)/)?.[1] ?? "";
  const name = stdout.match(/ProductName:\s*(.+)/)?.[1] ?? "";

  return {
    name,
    version,
  };
};

function getPropertyViaWithDefault<T, Property extends string>(
  data: object,
  names: Property[],
  defaultValue: T,
): T {
  for (const name of names) {
    const ret: T = getPropertyWithDefault(data, name, defaultValue);

    if (ret !== defaultValue) {
      return ret;
    }
  }

  return defaultValue;
}

function getPropertyWithDefault<T, Property extends string>(
  data: object,
  name: Property,
  defaultValue: T,
): T {
  if (!data.hasOwnProperty(name)) {
    return defaultValue;
  }

  const value = (data as { [K in Property]: T })[name];

  // NB. this check won't work for object instances
  if (typeof value !== typeof defaultValue) {
    return defaultValue;
  }

  return value;
}

const getLinuxInfo = async (): Promise<{
  name: string;
  version: string;
}> => {
  let data: object = {};

  try {
    data = releaseInfo({ mode: "sync" });
    // eslint-disable-next-line no-console
    console.log(data);
  } catch (e) {
    core.debug(`Error collecting release info: ${e}`);
  }

  return {
    name: getPropertyViaWithDefault(
      data,
      ["id", "name", "pretty_name", "id_like"],
      "unknown",
    ),
    version: getPropertyViaWithDefault(
      data,
      ["version_id", "version", "version_codename"],
      "unknown",
    ),
  };
};

export const platform = os.platform();
export const arch = os.arch();
export const isWindows = platform === "win32";
export const isMacOS = platform === "darwin";
export const isLinux = platform === "linux";

export async function getDetails(): Promise<{
  name: string;
  platform: string;
  arch: string;
  version: string;
  isWindows: boolean;
  isMacOS: boolean;
  isLinux: boolean;
}> {
  return {
    ...(await (isWindows
      ? getWindowsInfo()
      : isMacOS
        ? getMacOsInfo()
        : getLinuxInfo())),
    platform,
    arch,
    isWindows,
    isMacOS,
    isLinux,
  };
}
