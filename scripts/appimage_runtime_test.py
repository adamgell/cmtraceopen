import copy
import json
import tempfile
import unittest
from pathlib import Path

try:
    from appimage_runtime import contract
except ImportError:
    contract = None


class ContractTests(unittest.TestCase):
    def api(self, name):
        self.assertIsNotNone(contract, "runtime contract is not implemented")
        function = getattr(contract, name, None)
        self.assertTrue(callable(function), name + " is not implemented")
        return function

    def test_exact_artifact_and_source_binding(self):
        validate = self.api("validate_binding")
        report = dict(build=dict(source_commit="0a1bb21add1e7d331d4f4e2a00be8c317240bebf", built_commit="9433d28d28db986c0a2204b22cf20a7643d7f3df", built_tree="5481bee5fc7f503b075ed6501bc9556db65de76e", image=dict(GITHUB_RUN_ID="37222916777", GITHUB_RUN_ATTEMPT="1")), inspection=dict(sha256="fe80fa10c11b0dbd16198579169a08e4f2ed5ab5e72da876c3ec0197153b9873"))
        digest=report["inspection"]["sha256"]
        validate(report, digest)
        for field in ["source_commit", "built_commit", "built_tree"]:
            bad=copy.deepcopy(report); bad["build"][field]="0"*40
            with self.subTest(field=field), self.assertRaises(ValueError): validate(bad,digest)
        for field in ["GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"]:
            bad=copy.deepcopy(report); bad["build"]["image"][field]="2"
            with self.subTest(field=field), self.assertRaises(ValueError): validate(bad,digest)
        with self.assertRaises(ValueError): validate(report,"0"*64)
        bad=copy.deepcopy(report); bad["inspection"]["sha256"]="0"*64
        with self.assertRaises(ValueError): validate(bad,digest)

    def test_network_only_namespace_and_unprivileged_identity(self):
        validate=self.api("validate_identity")
        status=dict(Uid="1234 1234 1234 1234", Gid="1235 1235 1235 1235", Groups="", CapInh="0000", CapPrm="0000", CapEff="0000", CapAmb="0000", NoNewPrivs="0")
        host=dict(net="net:[1]",mnt="mnt:[2]",pid="pid:[3]",user="user:[4]")
        current={**host,"net":"net:[5]"}
        links=[dict(ifname="lo",flags=["LOOPBACK"])]
        validate(status,1234,1235,host,current,links,[])
        for field,value in [("Uid","0 0 0 0"),("Gid","1235 0 1235 1235"),("Groups","27"),("CapInh","1"),("CapPrm","1"),("CapEff","1"),("CapAmb","1"),("NoNewPrivs","1")]:
            with self.subTest(field=field), self.assertRaises(ValueError): validate({**status,field:value},1234,1235,host,current,links,[])
        for namespace in host:
            bad={**current,namespace:host[namespace] if namespace=="net" else "changed"}
            with self.subTest(namespace=namespace), self.assertRaises(ValueError): validate(status,1234,1235,host,bad,links,[])
        with self.assertRaises(ValueError): validate(status,1234,1235,host,current,[dict(ifname="eth0",flags=[])],[])
        with self.assertRaises(ValueError): validate(status,1234,1235,host,current,[dict(ifname="lo",flags=["UP"])],[])
        with self.assertRaises(ValueError): validate(status,1234,1235,host,current,links,[dict(dst="default")])

    def test_live_fuse_mount_must_contain_actual_application_executable(self):
        find=self.api("fuse_mount")
        line="53 29 0:49 / /tmp/.mount_CMTrace ro,nosuid,nodev - fuse.CMTrace AppImage ro,user_id=1234,group_id=1235"
        self.assertEqual(find(line,"/tmp/.mount_CMTrace/usr/bin/cmtrace-open"),"/tmp/.mount_CMTrace")
        for mounts,exe in [(line.replace("fuse.CMTrace","squashfs"),"/tmp/.mount_CMTrace/usr/bin/cmtrace-open"),(line,"/tmp/extracted/usr/bin/cmtrace-open"),(line,"/tmp/.mount_CMTrace/not-cmtrace"),(line.replace(" ro,nosuid", " rw,nosuid"),"/tmp/.mount_CMTrace/usr/bin/cmtrace-open")]:
            with self.subTest(exe=exe), self.assertRaises(ValueError): find(mounts,exe)

    def test_process_binding_excludes_unrelated_same_uid_processes(self):
        descendants=self.api("descendant_pids")
        table={10:1,11:10,12:11,13:1,14:13}
        self.assertEqual(descendants(table,10),{10,11,12})

    def test_fixture_rows_require_exact_inclusions_exclusions_and_count(self):
        validate=self.api("validate_rows")
        rows=[dict(role="option",text="time JAMMY_OPEN_ALPHA",selected=False),dict(role="option",text="time JAMMY_FIND_BETA",selected=True),dict(role="option",text="time JAMMY_FILTER_GAMMA",selected=False)]
        validate(rows,["JAMMY_OPEN_ALPHA","JAMMY_FIND_BETA","JAMMY_FILTER_GAMMA"])
        validate([rows[2]],["JAMMY_FILTER_GAMMA"])
        for bad in [rows,[],[rows[2],rows[2]],[dict(role="cell",text="JAMMY_FILTER_GAMMA",selected=False)]]:
            with self.subTest(rows=bad), self.assertRaises(ValueError): validate(bad,["JAMMY_FILTER_GAMMA"])

    def test_evidence_rejects_unknown_status_checks_and_freeform_app_text(self):
        clean=self.api("sanitize_case")
        valid=dict(case="ordinary",status="passed",reason="ok",checks={"fuse":True,"open":True,"find":True,"filter":True,"tail":True,"reopen":True,"exited":True},counts=[3,1,3,4,4])
        self.assertEqual(clean(valid),valid)
        for change in [dict(reason="secret raw log"),dict(status="maybe"),dict(raw_log="secret"),dict(checks={"fuse":True}),dict(counts=[3,1,3,3,4])]:
            with self.subTest(change=change), self.assertRaises(ValueError): clean({**valid,**change})


if __name__ == "__main__":
    unittest.main()
