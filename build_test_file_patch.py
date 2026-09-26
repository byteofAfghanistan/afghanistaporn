                                                                                 
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess

import build_test_installer as full

ROOT = full.ROOT
HELPER = "tools/frida_play_connect.py"
BASES = (
    ("single2", "installer/build final single 2/build-manifest.json", "21a0862071129eb64039cd06451202243c25ca7279dbdc4844191e3154e72bef"),
    ("patched-single2", "installer/build launcher patch 3/payload/next-manifest.json", "639577be793020997d8088cfd7edd5f219ee1f50e99bffc88648496041c3a497"),
    ("single3", "installer/build final single 3/build-manifest.json", "3aa3b3c89ee2f3869cd5ee32b7f0260d0aa45579ae77c4fd00c9754b3f106170"),
    ("network-single2", "installer/build network patch 1/payload/target-00.json", "7a5f572cddcef3221d22ffe9bb28523b53fd118448f27655326cc1da373f0de9"),
    ("network-patched-single2", "installer/build network patch 1/payload/target-01.json", "b00c0cad0ff8c0dd02f7e5d62ef44b416db01669bd600b3b4219b9312a8eb3a9"),
    ("network-single3", "installer/build network patch 1/payload/target-02.json", "ae815d525003c365272f02d68ac060b77111e1b7974f6345eceb9b587700d5e0"),
)
INPUTS = ("installer/ClientFilePatch.cs", "installer/FilePatch.iss", "tools/build_test_file_patch.py",
          "tools/build_test_installer.py", "loader/zula.ico", HELPER)


def encoded(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def build(stage, compile_setup=True):
    stage = Path(stage).absolute()
    if stage.exists():
        raise ValueError("Use a fresh output stage")
    snapshots = {name: full.read(full.source_file(ROOT, name)) for name in INPUTS}
    helper = snapshots[HELPER]
    if not 1 <= len(helper) <= 1024 * 1024:
        raise ValueError("Unexpected helper size")
    replacement = {"path": HELPER, "package": "replacement-00.bin", "size": len(helper), "sha256": full.sha(helper)}
    variants = []; targets = {}; operator = []
    for index, (label, relative, pinned) in enumerate(BASES):
        raw = full.read(full.source_file(ROOT, relative))
        if full.sha(raw) != pinned:
            raise ValueError("Published baseline manifest changed: " + label)
        base = json.loads(raw)
        if len(base["files"]) != 461 or len({row["path"].lower() for row in base["files"]}) != 461:
            raise ValueError("Unexpected baseline member set")
        previous = next(row for row in base["files"] if row["path"] == HELPER)
        if previous["sha256"] == replacement["sha256"]:
            raise ValueError("No helper change")
        target = copy.deepcopy(base)
        for row in target["files"]:
            if row["path"] == HELPER:
                row.update(size=len(helper), sha256=replacement["sha256"])
        found = False
        for row in target["sourceInputs"]:
            if row["path"] == HELPER:
                row["sha256"] = replacement["sha256"]; found = True
        if not found:
            raise ValueError("Missing original source input")
        target["totalBytes"] = sum(row["size"] for row in target["files"])
        target["clientFilePatch"] = {"version": 2, "baseManifestSha256": pinned,
            "installedWrites": [HELPER, "client-payload-manifest.json"],
            "sourceInputs": [{"path": name, "sha256": full.sha(value)} for name, value in sorted(snapshots.items())]}
        value = encoded(target); name = "target-%02d.json" % index; targets[name] = value
        variants.append({"baseManifestSha256": pinned, "targetManifestSha256": full.sha(value),
                         "targetManifestFile": name, "files": base["files"]})
        operator.append({"label": label, "baseManifestSha256": pinned, "targetManifestSha256": full.sha(value)})
    if len({json.loads(target)["backendReleaseSha256"] for target in targets.values()}) != 1:
        raise ValueError("Mixed backend baselines")
    plan = encoded({"version": 2, "replacements": [replacement], "variants": variants})
    if len(plan) > 1024 * 1024:
        raise ValueError("Patch plan exceeds the publisher's bounded input")
    stage.mkdir(parents=True); payload = stage / "payload"; payload.mkdir()
    compiled = stage / "compiled"; compiled.mkdir()
    (payload / "patch-plan.json").write_bytes(plan)
    (payload / replacement["package"]).write_bytes(helper)
    for name, value in targets.items():
        (payload / name).write_bytes(value)
    pin = compiled / "BuildPin.cs"
    pin.write_text('namespace ZulaClientFilePatch {internal static class BuildPin {internal const string PlanSha256="' + full.sha(plan) + '";}}', "utf-8")
    captured = compiled / "ClientFilePatch.cs"; captured.write_bytes(snapshots["installer/ClientFilePatch.cs"])
    compiler = Path(os.environ["WINDIR"]) / "Microsoft.NET/Framework64/v4.0.30319/csc.exe"
    subprocess.run([str(compiler), "/nologo", "/target:winexe", "/platform:anycpu", "/optimize+", "/warnaserror+", "/codepage:65001",
                    "/reference:System.Core.dll", "/reference:System.Web.Extensions.dll", "/main:ZulaClientFilePatch.Updater",
                    "/out:" + str(payload / "ZulaUpdate.exe"), str(captured), str(pin)], check=True, capture_output=True)
    def recheck():
        for name, value in snapshots.items():
            if full.read(full.source_file(ROOT, name)) != value:
                raise ValueError("Source changed during build: " + name)
    recheck()
    manifest = {"version": 2, "kind": "exact-client-helper-patch", "variants": operator,
        "backendReleaseSha256": json.loads(next(iter(targets.values())))["backendReleaseSha256"],
        "installedWrites": [HELPER, "client-payload-manifest.json"],
        "sourceInputs": [{"path": name, "sha256": full.sha(value)} for name, value in sorted(snapshots.items())],
        "files": [{"path": path.name, "size": path.stat().st_size, "sha256": full.sha(path.read_bytes())} for path in sorted(payload.iterdir())]}
    (stage / "build-manifest.json").write_bytes(encoded(manifest))
    if compile_setup:
        output = stage / "distribution"; output.mkdir()
        subprocess.run(["C:/Program Files (x86)/Inno Setup 6/ISCC.exe", "/Qp", "/DPatchPayload=" + str(payload),
                        "/DOutputPath=" + str(output), str(ROOT / "installer/FilePatch.iss")], check=True)
        recheck()
        size, digest = full.stream_hash(output / "Zula-Oyun-Guncelle.exe")
        (stage / "setup-sha256.json").write_bytes(encoded({"file": "Zula-Oyun-Guncelle.exe", "size": size, "sha256": digest,
            "manifestSha256": full.sha(encoded(manifest)), "variants": operator}))
    print(json.dumps({"stage": str(stage), "helperSha256": replacement["sha256"], "variants": operator}))
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=Path, required=True)
    args = parser.parse_args(); build(args.stage)
