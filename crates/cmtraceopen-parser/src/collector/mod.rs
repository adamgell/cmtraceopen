// Pure parts of the evidence-collection pipeline. The on-device collection
// engine itself (running subprocesses, reading files from disk, writing a
// bundle to a target dir) is native-only and stays in src-tauri/src/collector;
// this crate holds the data types + embedded profile catalog that the engine
// (and the agent, once it lands) both consume.

pub mod env_expand;
pub mod profile;
pub mod types;

#[cfg(test)]
mod cross_profile_tests {
    use std::collections::HashSet;

    use serde_json::Value;

    use super::types::CollectionProfile;

    const TARGETED_PROFILE_JSON: &str =
        include_str!("../../../../scripts/collection/intune-evidence-profile.json");
    const REFERENCE_PROFILE_JSON: &str =
        include_str!("../../../../references/collection/intune-evidence-profile.json");
    const EMBEDDED_PROFILE_JSON: &str = include_str!("profile_data.json");
    const TARGETED_README: &str = include_str!("../../../../scripts/collection/README.md");
    const REFERENCE_README: &str = include_str!("../../../../references/collection/README.md");

    #[test]
    fn esp_profile_has_required_registry_families() {
        let profile = CollectionProfile::embedded();
        let required_paths = [
            r"HKLM\SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot",
            r"HKLM\SOFTWARE\Microsoft\Provisioning\AutopilotSettings",
            r"HKLM\SOFTWARE\Microsoft\Provisioning\OMADM",
            r"HKLM\SOFTWARE\Microsoft\Provisioning\NodeCache\CSP",
            r"HKLM\SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking",
            r"HKLM\SOFTWARE\Microsoft\Enrollments\{enrollment-id}\FirstSync",
            r"HKLM\SOFTWARE\Microsoft\EnterpriseDesktopAppManagement",
            r"HKLM\SOFTWARE\Microsoft\OfficeCSP",
            r"HKLM\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps",
        ];

        for required_path in required_paths {
            assert!(
                profile
                    .registry
                    .iter()
                    .any(|item| registry_export_covers(&item.path, required_path)),
                "embedded profile does not cover required ESP registry path: {required_path}"
            );
        }
    }

    #[test]
    fn esp_profile_has_wmansvc_autopilot_json() {
        let profile = CollectionProfile::embedded();
        let expected_suffix = r"\ServiceState\wmansvc\AutopilotDDSZTDFile.json";
        let export = profile
            .exports
            .iter()
            .find(|item| {
                item.source_path
                    .to_ascii_lowercase()
                    .ends_with(&expected_suffix.to_ascii_lowercase())
            })
            .expect("embedded profile must collect the exact wmansvc AutopilotDDSZTDFile.json");

        assert!(!export.source_path.contains('*'));
        assert_eq!(
            export.file_name.as_deref(),
            Some("AutopilotDDSZTDFile.json")
        );
        assert!(export.parse_hints.iter().any(|hint| hint == "json"));
    }

    #[test]
    fn esp_profile_has_structured_hardware_and_do_outputs() {
        let profile = CollectionProfile::embedded();

        for id in ["esp-os-facts", "esp-hardware-facts", "esp-tpm-facts"] {
            let command = profile
                .commands
                .iter()
                .find(|item| item.id == id)
                .unwrap_or_else(|| panic!("embedded profile is missing structured output: {id}"));
            let arguments = command.arguments.join(" ");
            assert!(arguments.contains("ConvertTo-Json"), "{id} must emit JSON");
            assert!(command.parse_hints.iter().any(|hint| hint == "json"));
            assert!(!arguments.contains("DeviceHardwareData"));
            assert!(!arguments.to_ascii_lowercase().contains("hardware hash"));
        }

        let hardware = profile
            .commands
            .iter()
            .find(|item| item.id == "esp-hardware-facts")
            .expect("hardware facts command");
        let hardware_arguments = hardware.arguments.join(" ");
        for property in ["Manufacturer", "Model", "SerialNumber"] {
            assert!(
                hardware_arguments.contains(property),
                "hardware facts omit {property}"
            );
        }

        let do_commands: Vec<_> = profile
            .commands
            .iter()
            .filter(|item| item.id.starts_with("delivery-optimization-"))
            .collect();
        assert!(
            !do_commands.is_empty(),
            "embedded profile must collect DO evidence"
        );
        for command in do_commands {
            let arguments = command.arguments.join(" ");
            assert!(
                arguments.contains("Select-Object"),
                "{} is not field-filtered",
                command.id
            );
            assert!(
                arguments.contains("ConvertTo-Json"),
                "{} is not structured JSON",
                command.id
            );
            assert!(
                !arguments.contains("Format-List *"),
                "{} captures unbounded fields",
                command.id
            );
            assert!(command.parse_hints.iter().any(|hint| hint == "json"));
        }
    }

    #[test]
    fn profile_parse_hints_are_backward_compatible() {
        let legacy_json = r#"{
            "profileName": "legacy",
            "profileVersion": "1.0.0",
            "logs": [{"id":"log","family":"esp","sourcePattern":"C:\\\\Logs\\\\*.log","destinationFolder":"logs","notes":"legacy"}],
            "registry": [{"id":"reg","family":"esp","path":"HKLM\\\\Software","fileName":"state.reg","notes":"legacy"}],
            "eventLogs": [{"id":"event","family":"esp","sourcePattern":"C:\\\\Windows\\\\System32\\\\winevt\\\\Logs\\\\System.evtx","destinationFolder":"event-logs","notes":"legacy"}],
            "exports": [{"id":"export","family":"esp","sourcePath":"C:\\\\state.json","destinationFolder":"exports","fileName":"state.json","notes":"legacy"}],
            "commands": [{"id":"command","family":"esp","command":"cmd.exe","arguments":["/c","ver"],"fileName":"version.txt","notes":"legacy"}]
        }"#;

        let profile: CollectionProfile =
            serde_json::from_str(legacy_json).expect("legacy profile without parseHints");
        assert!(profile.logs[0].parse_hints.is_empty());
        assert!(profile.registry[0].parse_hints.is_empty());
        assert!(profile.event_logs[0].parse_hints.is_empty());
        assert!(profile.exports[0].parse_hints.is_empty());
        assert!(profile.commands[0].parse_hints.is_empty());
    }

    #[test]
    fn esp_profile_artifact_ids_are_unique() {
        let profile = CollectionProfile::embedded();
        let mut seen = HashSet::new();
        for id in profile.artifact_ids() {
            assert!(seen.insert(id), "duplicate embedded artifact id: {id}");
        }
        assert!(profile.has_unique_artifact_ids());
        assert_eq!(seen.len(), profile.total_items());
    }

    #[test]
    fn cross_profile_targeted_and_reference_profiles_match() {
        let targeted = parse_profile(TARGETED_PROFILE_JSON);
        let reference = parse_profile(REFERENCE_PROFILE_JSON);
        assert_eq!(
            targeted, reference,
            "targeted and reference profiles drifted"
        );
    }

    #[test]
    fn cross_profile_required_esp_contract_is_present() {
        for (name, profile) in [
            ("targeted", parse_profile(TARGETED_PROFILE_JSON)),
            ("reference", parse_profile(REFERENCE_PROFILE_JSON)),
            ("embedded", parse_profile(EMBEDDED_PROFILE_JSON)),
        ] {
            assert_required_profile_contract(name, &profile);
        }
    }

    #[test]
    fn cross_profile_registry_exports_are_deduplicated() {
        for (name, profile) in [
            ("targeted", parse_profile(TARGETED_PROFILE_JSON)),
            ("reference", parse_profile(REFERENCE_PROFILE_JSON)),
        ] {
            let paths: Vec<String> = profile_array(&profile, "registry")
                .iter()
                .filter_map(|item| item.get("path").and_then(Value::as_str))
                .map(normalize_registry_path)
                .collect();
            for (index, parent) in paths.iter().enumerate() {
                for (other_index, child) in paths.iter().enumerate() {
                    if index != other_index && child.starts_with(&format!("{parent}\\")) {
                        panic!(
                            "{name} profile duplicates parent registry export {parent} with child {child}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn cross_profile_documentation_matches_safety_contract() {
        assert_eq!(
            TARGETED_README, REFERENCE_README,
            "collection READMEs drifted"
        );
        let readme = TARGETED_README.to_ascii_lowercase();
        for required_phrase in [
            "read-only",
            "sensitive fields",
            "raw hardware hash",
            "firstsync",
            "win32apps",
        ] {
            assert!(
                readme.contains(required_phrase),
                "collection README omits safety contract phrase: {required_phrase}"
            );
        }
    }

    fn assert_required_profile_contract(name: &str, profile: &Value) {
        let registry = profile_array(profile, "registry");
        for required_path in [
            r"HKLM\SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot",
            r"HKLM\SOFTWARE\Microsoft\Provisioning\AutopilotSettings",
            r"HKLM\SOFTWARE\Microsoft\Provisioning\OMADM",
            r"HKLM\SOFTWARE\Microsoft\Provisioning\NodeCache\CSP",
            r"HKLM\SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking",
            r"HKLM\SOFTWARE\Microsoft\Enrollments\{enrollment-id}\FirstSync",
            r"HKLM\SOFTWARE\Microsoft\EnterpriseDesktopAppManagement",
            r"HKLM\SOFTWARE\Microsoft\OfficeCSP",
            r"HKLM\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps",
        ] {
            assert!(
                registry.iter().any(|item| {
                    item.get("path")
                        .and_then(Value::as_str)
                        .is_some_and(|path| registry_export_covers(path, required_path))
                }),
                "{name} profile does not cover {required_path}"
            );
        }

        let required_ids = [
            "ime-logs",
            "mdm-enrollments",
            "autopilot-diagnostics",
            "autopilot-settings",
            "autopilot-esp-diagnostics",
            "ime-state",
            "provisioning-nodecache-csp",
            "enterprise-desktop-app-mgmt",
            "office-csp",
            "autopilot-dds-ztd-wmansvc",
            "delivery-optimization-status",
            "delivery-optimization-perf-snap",
            "esp-os-facts",
            "esp-hardware-facts",
            "esp-tpm-facts",
        ];
        let ids = profile_artifact_ids(profile);
        for required_id in required_ids {
            assert!(
                ids.contains(required_id),
                "{name} profile is missing {required_id}"
            );
        }

        let all_id_count = ["logs", "registry", "eventLogs", "exports", "commands"]
            .iter()
            .map(|category| profile_array(profile, category).len())
            .sum::<usize>();
        assert_eq!(ids.len(), all_id_count, "{name} profile has duplicate IDs");

        let exports = profile_array(profile, "exports");
        let wmansvc_suffix = r"\ServiceState\wmansvc\AutopilotDDSZTDFile.json";
        assert!(
            exports.iter().any(|item| {
                item.get("sourcePath")
                    .and_then(Value::as_str)
                    .is_some_and(|path| {
                        path.to_ascii_lowercase()
                            .ends_with(&wmansvc_suffix.to_ascii_lowercase())
                            && !path.contains('*')
                    })
            }),
            "{name} profile lacks the exact wmansvc Autopilot JSON"
        );

        let commands = profile_array(profile, "commands");
        for command_id in ["esp-os-facts", "esp-hardware-facts", "esp-tpm-facts"] {
            let command = command_by_id(commands, command_id, name);
            let arguments = command_arguments(command);
            assert!(
                arguments.contains("Select-Object") || arguments.contains("[pscustomobject]@"),
                "{name} {command_id} does not select bounded fields"
            );
            assert!(arguments.contains("ConvertTo-Json"));
            let lowered = arguments.to_ascii_lowercase();
            assert!(!lowered.contains("devicehardwaredata"));
            assert!(!lowered.contains("decodehwhash"));
            assert!(!lowered.contains("hardware hash"));
        }
        for command_id in [
            "delivery-optimization-status",
            "delivery-optimization-perf-snap",
        ] {
            let command = command_by_id(commands, command_id, name);
            let arguments = command_arguments(command);
            assert!(
                arguments.contains("Select-Object"),
                "{name} {command_id} is unfiltered"
            );
            assert!(
                arguments.contains("ConvertTo-Json"),
                "{name} {command_id} is unstructured"
            );
            assert!(!arguments.contains("Format-List *"));
        }

        let event_families = normalized_event_families(profile);
        for required_family in [
            "aad",
            "device-management",
            "modern-deployment",
            "provisioning",
            "shell-core",
            "user-device-registration",
        ] {
            assert!(
                event_families.contains(required_family),
                "{name} profile lacks normalized event family {required_family}"
            );
        }

        if profile_array(profile, "eventLogs")
            .iter()
            .any(|item| item.get("channel").is_some())
        {
            let channels: HashSet<&str> = profile_array(profile, "eventLogs")
                .iter()
                .filter_map(|item| item.get("channel").and_then(Value::as_str))
                .collect();
            for channel in [
                "Microsoft-Windows-DeliveryOptimization/Operational",
                "Microsoft-Windows-Time-Service/Operational",
            ] {
                assert!(channels.contains(channel), "{name} profile lacks {channel}");
            }
        }
    }

    fn parse_profile(json: &str) -> Value {
        serde_json::from_str(json).expect("valid collection profile JSON")
    }

    fn profile_array<'a>(profile: &'a Value, key: &str) -> &'a Vec<Value> {
        profile
            .get(key)
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("profile is missing array: {key}"))
    }

    fn profile_artifact_ids(profile: &Value) -> HashSet<&str> {
        ["logs", "registry", "eventLogs", "exports", "commands"]
            .iter()
            .flat_map(|category| profile_array(profile, category))
            .filter_map(|item| item.get("id").and_then(Value::as_str))
            .collect()
    }

    fn command_by_id<'a>(commands: &'a [Value], id: &str, profile_name: &str) -> &'a Value {
        commands
            .iter()
            .find(|item| item.get("id").and_then(Value::as_str) == Some(id))
            .unwrap_or_else(|| panic!("{profile_name} profile lacks command {id}"))
    }

    fn command_arguments(command: &Value) -> String {
        command
            .get("arguments")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn normalized_event_families(profile: &Value) -> HashSet<&'static str> {
        let mut families = HashSet::new();
        for item in profile_array(profile, "eventLogs") {
            let value = item
                .get("channel")
                .or_else(|| item.get("sourcePattern"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_ascii_lowercase();
            for (family, needles) in [
                ("aad", &["aad"][..]),
                ("device-management", &["devicemanagement"][..]),
                ("modern-deployment", &["moderndeployment"][..]),
                ("provisioning", &["provisioning-"][..]),
                ("shell-core", &["shell-core"][..]),
                (
                    "user-device-registration",
                    &["user device", "user*device"][..],
                ),
            ] {
                if needles.iter().any(|needle| value.contains(needle)) {
                    families.insert(family);
                }
            }
        }
        families
    }

    fn registry_export_covers(exported_path: &str, required_path: &str) -> bool {
        let exported = normalize_registry_path(exported_path);
        let required = normalize_registry_path(required_path);
        required == exported || required.starts_with(&format!("{exported}\\"))
    }

    fn normalize_registry_path(path: &str) -> String {
        path.trim_matches('\\')
            .replace("HKEY_LOCAL_MACHINE", "HKLM")
            .to_ascii_uppercase()
    }
}
