/**
 * The two `ensureLogViewVisible` triggers a workspace can ask to keep its view for
 * (`WorkspaceCapabilities.keepsViewOnLogLoad`). Every other trigger is a plain string at its call
 * site, and nothing here narrows what `ensureLogViewVisible` accepts.
 *
 * They are the two the Event Logs "Add log source" flow produces: opening a log's tab, and the
 * multi-file load.
 */

/** AppShell's active-tab effect, whenever the active tab changes. */
export const TAB_SWITCH_TRIGGER = "tab-switch";

/** `loadFilesAsLogSource`, once the files it parsed have been applied. */
export const MULTI_FILE_OPEN_TRIGGER = "multi-file-open";
