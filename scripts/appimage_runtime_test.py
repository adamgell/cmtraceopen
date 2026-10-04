import copy
import json
import tempfile
import os
import io
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

    def test_namespace_command_drops_privileges_without_disabling_fuse_helpers(self):
        command=self.api("namespace_command")(1234,1235,Path("/tmp/owned"))
        self.assertEqual(command[:4],["/usr/bin/unshare","--net","--","/usr/bin/setpriv"])
        self.assertIn("--reuid=1234",command)
        self.assertIn("--regid=1235",command)
        for item in ["--clear-groups","--inh-caps=-all","--ambient-caps=-all","-i","PATH=/usr/bin:/bin:/usr/sbin:/sbin","/usr/bin/python3"]:
            self.assertIn(item,command)
        self.assertEqual(command[-3:],["-m","appimage_runtime.session","/tmp/owned"])
        for item in command:
            self.assertFalse(item.startswith(("--mount","--pid","--user","--no-new-privs","--bounding-set","--net=")),item)
        for uid,gid in [(0,1235),(1234,0),(-1,1235)]:
            with self.assertRaises(ValueError): self.api("namespace_command")(uid,gid,Path("/tmp/owned"))

    def test_evidence_reader_rejects_symlinks_hardlinks_oversize_and_wrong_owner(self):
        read=self.api("read_owned_file")
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); file=root/"result.json"; file.write_bytes(b"{}")
            self.assertEqual(read(file,os.getuid(),10),b"{}")
            with self.assertRaises(ValueError): read(file,os.getuid()+1,10)
            with self.assertRaises(ValueError): read(file,os.getuid(),1)
            link=root/"link"; link.symlink_to(file)
            with self.assertRaises((ValueError,OSError)): read(link,os.getuid(),10)
            os.link(file,root/"hardlink")
            with self.assertRaises(ValueError): read(file,os.getuid(),10)
            with self.assertRaises(ValueError): read(root,os.getuid(),10)

    def test_screenshot_is_decoded_reencoded_and_metadata_removed(self):
        from PIL import Image, PngImagePlugin
        clean=self.api("sanitize_png")
        original=io.BytesIO(); meta=PngImagePlugin.PngInfo(); meta.add_text("private","must not upload")
        Image.new("RGB",(20,20),"white").save(original,format="PNG",pnginfo=meta)
        output=clean(original.getvalue())
        image=Image.open(io.BytesIO(output))
        self.assertEqual(image.size,(20,20))
        self.assertNotIn("private",image.info)
        self.assertNotIn(b"must not upload",output)
        bad=io.BytesIO(); Image.new("RGB",(1300,901)).save(bad,format="PNG")
        for data in [b"not a screenshot",bad.getvalue()]:
            with self.assertRaises(ValueError): clean(data)

    def test_accessibility_roles_accept_listbox_options_not_tables(self):
        role=self.api("accessible_role")
        self.assertEqual(role("list box",[]),"listbox")
        self.assertEqual(role("list item",[]),"option")
        self.assertEqual(role("unknown",["xml-roles:option"]),"option")
        self.assertEqual(role("table",[]),"table")
        self.assertEqual(role("table cell",[]),"table cell")

    def test_exit_tracking_rejects_helpers_orphaned_before_shutdown_poll(self):
        try:
            from appimage_runtime import processes
        except ImportError:
            self.fail("launch process tracker is not implemented")
        initial={100:(1,10,"S"),200:(100,20,"S")}
        tracker=processes.LaunchTracker(100,initial)
        during={**initial,300:(100,30,"S"),301:(300,31,"S")}
        self.assertEqual(tracker.active(during),{300,301})
        # The launcher is gone, and both an observed helper and a newly created
        # helper have been adopted by our subreaper before the next snapshot.
        orphaned={**initial,301:(100,31,"S"),302:(100,32,"S")}
        self.assertEqual(tracker.active(orphaned),{301,302})
        self.assertEqual(tracker.active(initial),set())

    def test_exit_tracking_binds_pid_identity_and_excludes_existing_gui_services(self):
        try:
            from appimage_runtime import processes
        except ImportError:
            self.fail("launch process tracker is not implemented")
        initial={100:(1,10,"S"),200:(100,20,"S")}
        tracker=processes.LaunchTracker(100,initial)
        during={**initial,201:(200,21,"S"),300:(100,30,"S")}
        self.assertEqual(tracker.active(during),{300})
        # Reusing the old PID for an unrelated process does not make it ours.
        reused={**initial,300:(1,99,"S")}
        self.assertEqual(tracker.active(reused),set())
        self.assertEqual(tracker.active({**initial,301:(100,31,"Z")}),set())

    def test_exit_acceptance_waits_for_adopted_helper_and_live_mount(self):
        from appimage_runtime import processes, ui
        from unittest.mock import patch
        from types import SimpleNamespace
        initial={100:(1,10,"S"),200:(100,20,"S")}
        during={**initial,300:(100,30,"S"),301:(300,31,"S")}
        orphaned={**initial,301:(100,31,"S")}
        for current,mounts in [(orphaned,""),(initial,"53 1 0:1 / /tmp/live ro - fuse.AppImage image ro")]:
            controller=ui.Controller(Path("/tmp/owned"),"ordinary",None)
            controller.app=SimpleNamespace(pid=300,returncode=0,poll=lambda:0)
            controller.window="42"
            controller.proofs=[dict(mount_id=53)]
            controller.pids={300}  # Keeps the regression meaningful against the old implementation.
            controller.tracker=processes.LaunchTracker(100,initial)
            def must_wait(predicate,*args,**kwargs):
                self.assertFalse(predicate(),"exit accepted with a live helper or FUSE mount")
                raise ValueError("ui-assertion")
            with patch.object(ui,"command"), patch.object(ui,"key"), patch.object(ui,"poll",side_effect=must_wait), patch.object(ui,"status",side_effect=FileNotFoundError), patch.object(ui,"process_table",return_value={pid:row[0] for pid,row in current.items()}), patch.object(processes,"snapshot",side_effect=[during,current]), patch.object(Path,"read_text",return_value=mounts):
                with self.assertRaises(ValueError): controller.exit_app()

    def test_collection_rejects_missing_preflight_and_pass_without_screenshots(self):
        from appimage_runtime.host import collect
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); output=root/"sanitized"; output.mkdir()
            (root/"proof").mkdir()
            for case in contract.CASES:
                area=root/case/"out"; area.mkdir(parents=True)
                (area/"result.json").write_text(json.dumps(dict(case=case,status="passed",reason="ok",checks=dict.fromkeys(contract.CHECKS,True),counts=[3,1,3,4,4])))
            preflight,cases=collect(root,os.getuid(),output)
            self.assertEqual(preflight,{})
            self.assertTrue(all(case["reason"]=="evidence-invalid" for case in cases))
            (root/"proof/preflight.json").write_text(json.dumps(dict(identity=True,offline=True,bubblewrap=True,fuse_device=True)))
            proof=dict(pid=1234,mount_id=53,filesystem="fuse.CMTrace",payload_root_0755=True)
            for case in contract.CASES:
                (root/case/"out/fuse.json").write_text(json.dumps([proof,proof]))
            preflight,cases=collect(root,os.getuid(),output)
            self.assertTrue(preflight["offline"])
            self.assertTrue(all(case["reason"]=="evidence-invalid" for case in cases))

    def test_payload_proof_requires_root_owned_executable_regular_files(self):
        validate=self.api("validate_payload")
        import stat
        valid={name:dict(mode=stat.S_IFREG | 0o755,uid=0,gid=0) for name in ("AppRun","AppRun.wrapped","usr/bin/cmtrace-open")}
        validate(valid)
        for key,value in [("mode",stat.S_IFLNK | 0o755),("mode",stat.S_IFREG | 0o644),("uid",1234),("gid",1234)]:
            bad=copy.deepcopy(valid); bad["AppRun"][key]=value
            with self.assertRaises(ValueError): validate(bad)

    def test_fuse_evidence_rejects_paths_and_requires_two_launches_for_pass(self):
        validate=self.api("sanitize_fuse")
        proof=dict(pid=1234,mount_id=53,filesystem="fuse.CMTrace",payload_root_0755=True)
        self.assertEqual(validate([proof,dict(proof,pid=1235)],True),[proof,dict(proof,pid=1235)])
        for bad in [[proof],[dict(proof,filesystem="squashfs")],[dict(proof,path="private")],[dict(proof,payload_root_0755=False)]]:
            with self.assertRaises(ValueError): validate(bad,True)

    def test_cleanup_selects_only_owned_fuse_mounts_below_private_root(self):
        select=self.api("owned_fuse_mounts")
        lines="25 1 0:1 / / rw - ext4 /dev/sda rw\n53 25 0:49 / /tmp/task/ordinary/tmp/app ro - fuse.AppImage image ro,user_id=1234,group_id=1235\n54 25 0:50 / /tmp/unrelated ro - fuse.AppImage image ro,user_id=1234,group_id=1235"
        self.assertEqual(select(lines,1234,Path("/tmp/task")),["/tmp/task/ordinary/tmp/app"])
        for bad in [lines.replace("user_id=1234","user_id=999"),lines.replace("fuse.AppImage","squashfs")]:
            with self.assertRaises(ValueError): select(bad,1234,Path("/tmp/task"))
        self.assertEqual(select("25 1 0:1 / / rw - ext4 /dev/sda rw",1234,Path("/tmp/task")),[])

    def test_cleanup_unmount_drops_to_task_identity_and_uses_normal_fuse_helper(self):
        command=self.api("unmount_command")(1234,1235,"/tmp/task/ordinary/tmp/app")
        self.assertEqual(command[:4],["/usr/bin/setpriv","--reuid=1234","--regid=1235","--clear-groups"])
        self.assertEqual(command[-4:],["/usr/bin/fusermount3","-u","--","/tmp/task/ordinary/tmp/app"])
        self.assertIn("--inh-caps=-all",command)
        self.assertIn("--ambient-caps=-all",command)
        self.assertIn("-i",command)
        self.assertNotIn("--force",command)
        self.assertNotIn("-z",command)

    def test_process_cleanup_refuses_root_or_invalid_uid_before_proc_scan(self):
        from appimage_runtime.host import kill_owned
        from unittest.mock import patch
        with patch.object(Path,"iterdir") as scan:
            for uid in (0,-1):
                with self.assertRaises(ValueError): kill_owned(uid)
            scan.assert_not_called()

    def test_cleanup_requires_mount_disappearance_before_returning(self):
        from appimage_runtime import host
        from unittest.mock import patch
        cleanup=getattr(host,"cleanup_fuse",None)
        self.assertTrue(callable(cleanup),"bounded FUSE cleanup is not implemented")
        mount="53 25 0:49 / /tmp/task/ordinary/tmp/app ro - fuse.AppImage image ro,user_id=1234,group_id=1235"
        with patch.object(Path,"read_text",side_effect=[mount,""]), patch.object(host.subprocess,"run") as run:
            cleanup(Path("/tmp/task"),1234,1235)
            self.assertEqual(run.call_count,1)
            self.assertIn("/tmp/task/ordinary/tmp/app",run.call_args.args[0])
        with patch.object(Path,"read_text",return_value=mount), patch.object(host.subprocess,"run"):
            with self.assertRaises(ValueError): cleanup(Path("/tmp/task"),1234,1235)

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

    def test_fuse_metadata_skips_unrelated_mounts(self):
        metadata=self.api("fuse_metadata")
        mounts="25 1 0:1 / / rw - ext4 /dev/sda rw\n53 25 0:49 / /tmp/.mount_CMTrace ro,nosuid - fuse.CMTrace AppImage ro"
        self.assertEqual(metadata(mounts,"/tmp/.mount_CMTrace/usr/bin/cmtrace-open"),dict(mount_id=53,filesystem="fuse.CMTrace"))

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
