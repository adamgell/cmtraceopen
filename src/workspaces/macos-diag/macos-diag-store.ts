import { create } from "zustand";
import type {
  MacosDiagEnvironment,
  MacosDiagTabId,
  MacosIntuneLogScanResult,
  MacosProfilesResult,
  MacosDefenderResult,
  MacosPackagesResult,
  MacosPackageInfo,
  MacosPackageFiles,
  MacosUnifiedLogResult,
} from "./types";

export type EnvironmentPhase = "idle" | "scanning" | "ready" | "error";

interface MacosDiagState {
  // Environment
  environment: MacosDiagEnvironment | null;
  environmentPhase: EnvironmentPhase;
  environmentError: string | null;

  // Active tab
  activeTab: MacosDiagTabId;

  // Intune Logs tab
  intuneLogScan: MacosIntuneLogScanResult | null;
  intuneLogScanLoading: boolean;

  // Profiles tab
  profilesResult: MacosProfilesResult | null;
  profilesLoading: boolean;

  // Defender tab
  defenderResult: MacosDefenderResult | null;
  defenderLoading: boolean;

  // Packages tab
  packagesResult: MacosPackagesResult | null;
  packagesLoading: boolean;
  selectedPackageId: string | null;
  selectedPackageInfo: MacosPackageInfo | null;
  selectedPackageFiles: MacosPackageFiles | null;
  packageDrillLoading: boolean;

  // Unified Log tab
  unifiedLogResult: MacosUnifiedLogResult | null;
  unifiedLogLoading: boolean;
  unifiedLogPresetId: string;

  // Actions
  beginEnvironmentScan: () => void;
  setEnvironment: (env: MacosDiagEnvironment) => void;
  failEnvironmentScan: (error: string) => void;

  setActiveTab: (tab: MacosDiagTabId) => void;

  setIntuneLogScan: (result: MacosIntuneLogScanResult) => void;
  setIntuneLogScanLoading: (loading: boolean) => void;

  setProfilesResult: (result: MacosProfilesResult) => void;
  setProfilesLoading: (loading: boolean) => void;

  setDefenderResult: (result: MacosDefenderResult) => void;
  setDefenderLoading: (loading: boolean) => void;

  setPackagesResult: (result: MacosPackagesResult) => void;
  setPackagesLoading: (loading: boolean) => void;
  setSelectedPackageId: (id: string | null) => void;
  setSelectedPackageInfo: (info: MacosPackageInfo | null) => void;
  setSelectedPackageFiles: (files: MacosPackageFiles | null) => void;
  setPackageDrillLoading: (loading: boolean) => void;

  setUnifiedLogResult: (result: MacosUnifiedLogResult) => void;
  setUnifiedLogLoading: (loading: boolean) => void;
  setUnifiedLogPresetId: (presetId: string) => void;

  clear: () => void;
}

export const useMacosDiagStore = create<MacosDiagState>((set) => ({
  environment: null,
  environmentPhase: "idle",
  environmentError: null,

  activeTab: "intune-logs",

  intuneLogScan: null,
  intuneLogScanLoading: false,

  profilesResult: null,
  profilesLoading: false,

  defenderResult: null,
  defenderLoading: false,

  packagesResult: null,
  packagesLoading: false,
  selectedPackageId: null,
  selectedPackageInfo: null,
  selectedPackageFiles: null,
  packageDrillLoading: false,

  unifiedLogResult: null,
  unifiedLogLoading: false,
  unifiedLogPresetId: "managed-client",

  beginEnvironmentScan: () =>
    set({
      environmentPhase: "scanning",
      environmentError: null,
    }),

  setEnvironment: (env) =>
    set({
      environment: env,
      environmentPhase: "ready",
      environmentError: null,
    }),

  failEnvironmentScan: (error) =>
    set({
      environment: null,
      environmentPhase: "error",
      environmentError: error,
    }),

  setActiveTab: (tab) => set({ activeTab: tab }),

  setIntuneLogScan: (result) => set({ intuneLogScan: result, intuneLogScanLoading: false }),
  setIntuneLogScanLoading: (loading) => set({ intuneLogScanLoading: loading }),

  setProfilesResult: (result) => set({ profilesResult: result, profilesLoading: false }),
  setProfilesLoading: (loading) => set({ profilesLoading: loading }),

  setDefenderResult: (result) => set({ defenderResult: result, defenderLoading: false }),
  setDefenderLoading: (loading) => set({ defenderLoading: loading }),

  setPackagesResult: (result) => set({ packagesResult: result, packagesLoading: false }),
  setPackagesLoading: (loading) => set({ packagesLoading: loading }),
  setSelectedPackageId: (id) =>
    set({
      selectedPackageId: id,
      selectedPackageInfo: null,
      selectedPackageFiles: null,
    }),
  setSelectedPackageInfo: (info) => set({ selectedPackageInfo: info }),
  setSelectedPackageFiles: (files) => set({ selectedPackageFiles: files }),
  setPackageDrillLoading: (loading) => set({ packageDrillLoading: loading }),

  setUnifiedLogResult: (result) => set({ unifiedLogResult: result, unifiedLogLoading: false }),
  setUnifiedLogLoading: (loading) => set({ unifiedLogLoading: loading }),
  setUnifiedLogPresetId: (presetId) => set({ unifiedLogPresetId: presetId }),

  clear: () =>
    set({
      environment: null,
      environmentPhase: "idle",
      environmentError: null,
      activeTab: "intune-logs",
      intuneLogScan: null,
      intuneLogScanLoading: false,
      profilesResult: null,
      profilesLoading: false,
      defenderResult: null,
      defenderLoading: false,
      packagesResult: null,
      packagesLoading: false,
      selectedPackageId: null,
      selectedPackageInfo: null,
      selectedPackageFiles: null,
      packageDrillLoading: false,
      unifiedLogResult: null,
      unifiedLogLoading: false,
      unifiedLogPresetId: "managed-client",
    }),
}));
