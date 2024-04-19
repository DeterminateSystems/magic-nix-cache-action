// MIT, lifted from https://github.com/actions/toolkit/blob/5a736647a123ecf8582376bdaee833fbae5b3847/packages/core/src/platform.ts
// since it isn't in @actions/core 1.10.1 which is their current release as 2024-04-19
import os from "os";
import * as exec from "@actions/exec";
const getWindowsInfo = async () => {
    const { stdout: version } = await exec.getExecOutput('powershell -command "(Get-CimInstance -ClassName Win32_OperatingSystem).Version"', undefined, {
        silent: true,
    });
    const { stdout: name } = await exec.getExecOutput('powershell -command "(Get-CimInstance -ClassName Win32_OperatingSystem).Caption"', undefined, {
        silent: true,
    });
    return {
        name: name.trim(),
        version: version.trim(),
    };
};
const getMacOsInfo = async () => {
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
const getLinuxInfo = async () => {
    const { stdout } = await exec.getExecOutput("lsb_release", ["-i", "-r", "-s"], {
        silent: true,
    });
    const [name, version] = stdout.trim().split("\n");
    return {
        name,
        version,
    };
};
export const platform = os.platform();
export const arch = os.arch();
export const isWindows = platform === "win32";
export const isMacOS = platform === "darwin";
export const isLinux = platform === "linux";
export async function getDetails() {
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
