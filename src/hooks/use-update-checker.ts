import { useEffect, useCallback, useRef, useState } from "react";
import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";
import { getVersion } from "@tauri-apps/api/app";
import { platform } from "@tauri-apps/plugin-os";
import { useUiStore } from "../stores/ui-store";

const SKIPPED_VERSION_KEY = "cmtraceopen-skipped-update-version";
const GITHUB_RELEASES_URL = "https://github.com/adamgell/cmtraceopen/releases/latest";
const STARTUP_CHECK_DELAY_MS = 5000;

function getSkippedVersion(): string | null {
  try {
    return localStorage.getItem(SKIPPED_VERSION_KEY);
  } catch {
    return null;
  }
}

function setSkippedVersion(version: string): void {
  try {
    localStorage.setItem(SKIPPED_VERSION_KEY, version);
  } catch {
    // localStorage unavailable
  }
}

export interface UpdateInfo {
  available: boolean;
  currentVersion: string;
  newVersion?: string;
  releaseNotes?: string;
  canAutoUpdate: boolean;
  error?: string;
}

export function useUpdateChecker() {
  const [updateInfo, setUpdateInfo] = useState<UpdateInfo | null>(null);
  const [isChecking, setIsChecking] = useState(false);
  const [isDownloading, setIsDownloading] = useState(false);
  const [downloadProgress, setDownloadProgress] = useState(0);
  const startupCheckDone = useRef(false);
  const pendingUpdateRef = useRef<Update | null>(null);

  const checkForUpdates = useCallback(
    async (): Promise<UpdateInfo | null> => {
      setIsChecking(true);

      try {
        const [currentVersion, currentPlatform] = await Promise.all([
          getVersion(),
          platform(),
        ]);

        const canAutoUpdate = currentPlatform !== "linux";
        const update = await check();

        if (update) {
          pendingUpdateRef.current = update;
          const info: UpdateInfo = {
            available: true,
            currentVersion,
            newVersion: update.version,
            releaseNotes: update.body ?? undefined,
            canAutoUpdate,
          };
          setUpdateInfo(info);
          return info;
        }

        const info: UpdateInfo = {
          available: false,
          currentVersion,
          canAutoUpdate,
        };

        setUpdateInfo(info);
        return info;
      } catch (err) {
        console.error("[update-checker] failed to check for updates", err);
        const info: UpdateInfo = {
          available: false,
          currentVersion: "unknown",
          canAutoUpdate: false,
          error: String(err),
        };
        setUpdateInfo(info);
        return info;
      } finally {
        setIsChecking(false);
      }
    },
    []
  );

  const downloadAndInstall = useCallback(async () => {
    const update = pendingUpdateRef.current;
    if (!update) return;

    setIsDownloading(true);
    setDownloadProgress(0);

    try {
      let contentLength = 0;
      let downloaded = 0;

      await update.downloadAndInstall((event) => {
        switch (event.event) {
          case "Started":
            contentLength = event.data.contentLength ?? 0;
            break;
          case "Progress":
            downloaded += event.data.chunkLength;
            if (contentLength > 0) {
              setDownloadProgress(downloaded / contentLength);
            }
            break;
          case "Finished":
            setDownloadProgress(1);
            break;
        }
      });

      await relaunch();
    } catch (err) {
      console.error("[update-checker] download/install failed", err);
      setUpdateInfo((prev) =>
        prev ? { ...prev, error: String(err) } : null
      );
    } finally {
      setIsDownloading(false);
    }
  }, []);

  const openReleasePage = useCallback(() => {
    const newWindow = window.open(GITHUB_RELEASES_URL, "_blank", "noopener,noreferrer");
    if (newWindow) {
      newWindow.opener = null;
    }
  }, []);

  const skipVersion = useCallback((version: string) => {
    setSkippedVersion(version);
    setUpdateInfo(null);
    useUiStore.getState().setShowUpdateDialog(false);
  }, []);

  const dismiss = useCallback(() => {
    setUpdateInfo(null);
    useUiStore.getState().setShowUpdateDialog(false);
  }, []);

  // Startup check — silent, non-blocking, once
  useEffect(() => {
    if (startupCheckDone.current) return;
    startupCheckDone.current = true;

    const timer = setTimeout(async () => {
      const info = await checkForUpdates();
      if (info?.available && info.newVersion) {
        const skipped = getSkippedVersion();
        if (skipped === info.newVersion) {
          console.info("[update-checker] skipping version", info.newVersion);
          return;
        }
        useUiStore.getState().setShowUpdateDialog(true);
      }
    }, STARTUP_CHECK_DELAY_MS);

    return () => clearTimeout(timer);
  }, [checkForUpdates]);

  return {
    updateInfo,
    isChecking,
    isDownloading,
    downloadProgress,
    checkForUpdates,
    downloadAndInstall,
    openReleasePage,
    skipVersion,
    dismiss,
  };
}
