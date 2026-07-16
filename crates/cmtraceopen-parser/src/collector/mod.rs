// Pure parts of the evidence-collection pipeline. The on-device collection
// engine itself (running subprocesses, reading files from disk, writing a
// bundle to a target dir) is native-only and stays in src-tauri/src/collector;
// this crate holds the data types + embedded profile catalog that the engine
// (and the agent, once it lands) both consume.

pub mod env_expand;
pub mod profile;
pub mod types;

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::types::CollectionProfile;

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
