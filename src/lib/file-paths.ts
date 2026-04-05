/**
 * Shared file-path utilities.
 *
 * These helpers extract parts of a file path in a platform-agnostic way
 * (handling both `/` and `\` separators) so callers don't need to
 * re-implement the same split logic.
 *
 * NOTE: Several modules still carry their own local copies of these
 * functions (e.g. `getBaseName` in log-store, log-source, dsregcmd-source,
 * EvidenceBundleDialog, etc.).  Those will be migrated to import from here
 * during the component-split phase.
 */

/**
 * Return the filename portion of a path (everything after the last separator).
 *
 * Handles both forward-slash and back-slash separators so it works for
 * Windows paths received from the Tauri backend as well as POSIX paths.
 *
 * Returns `""` when `path` is `null` or empty.
 *
 * @example
 * getBaseName("C:\\Logs\\IME\\IntuneManagementExtension.log")
 * // => "IntuneManagementExtension.log"
 *
 * getBaseName("/var/log/install.log")
 * // => "install.log"
 */
export function getBaseName(path: string | null | undefined): string {
  if (!path) {
    return "";
  }

  return path.split(/[\\/]/).pop() ?? path;
}

/**
 * Return the directory portion of a path (everything before the last separator).
 *
 * Returns `null` when the path has no separator or is empty/null.
 * The returned string preserves the original separator style.
 *
 * @example
 * getDirectoryName("C:\\Logs\\IME\\IntuneManagementExtension.log")
 * // => "C:\\Logs\\IME"
 *
 * getDirectoryName("/var/log/install.log")
 * // => "/var/log"
 *
 * getDirectoryName("filename.log")
 * // => null
 */
export function getDirectoryName(path: string | null): string | null {
  if (!path) {
    return null;
  }

  // Normalize to forward slashes for finding the last separator position,
  // but slice the original string to preserve the caller's separator style.
  const normalized = path.replace(/\\/g, "/");
  const lastSeparator = normalized.lastIndexOf("/");
  if (lastSeparator <= 0) {
    return null;
  }

  return path.slice(0, lastSeparator);
}
