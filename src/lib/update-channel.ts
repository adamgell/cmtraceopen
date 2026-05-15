export type UpdateChannel = "stable" | "nightly";

const NIGHTLY_VERSION_MARKER = "-nightly.";
const STABLE_RELEASE_URL = "https://github.com/adamgell/cmtraceopen/releases/latest";
const NIGHTLY_RELEASE_URL = "https://github.com/adamgell/cmtraceopen/releases/tag/nightly";

export function getUpdateChannel(version: string): UpdateChannel {
  return version.includes(NIGHTLY_VERSION_MARKER) ? "nightly" : "stable";
}

export function getUpdateChannelLabel(channel: UpdateChannel): string {
  return channel === "nightly" ? "Nightly channel" : "Main channel";
}

export function getReleasePageUrl(channel: UpdateChannel): string {
  return channel === "nightly" ? NIGHTLY_RELEASE_URL : STABLE_RELEASE_URL;
}
