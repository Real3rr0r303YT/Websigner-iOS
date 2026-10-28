#!/usr/bin/env python3
"""
check_ipa.py - Validate an .ipa for iOS OTA (itms-services) installation and
optionally generate a matching manifest.plist.

Catches the usual causes of "<App> could not be installed at this time":
  - wrong archive layout (no Payload/<Name>.app/)
  - simulator build or non-arm64 binary
  - unsigned app, or App Store distribution profile (not installable OTA)
  - expired provisioning profile
  - profile App ID that doesn't match CFBundleIdentifier
  - device UDID missing from an ad-hoc / development profile
  - app extensions whose bundle IDs aren't prefixed with the app's bundle ID

Usage:
  python3 tools/check_ipa.py WebSigner.ipa
  python3 tools/check_ipa.py WebSigner.ipa --udid 00008110-001A2B3C4D5E6F70
  python3 tools/check_ipa.py WebSigner.ipa \
      --write-manifest manifest.plist \
      --ipa-url https://github.com/OWNER/REPO/releases/download/v1.0.0/WebSigner.ipa \
      --display-image https://owner.github.io/REPO/assets/icon-57.png \
      --full-size-image https://owner.github.io/REPO/assets/icon-512.png

Exit code is 1 if any check fails. Python 3.8+ standard library only.
"""

import argparse
import datetime as dt
import fnmatch
import plistlib
import struct
import sys
import zipfile

CPU_TYPE_ARM64 = 0x0100000C
MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF


class Report:
    def __init__(self):
        self.failures = 0

    def ok(self, msg):
        print(f"  [ OK ] {msg}")

    def warn(self, msg):
        print(f"  [WARN] {msg}")

    def fail(self, msg):
        self.failures += 1
        print(f"  [FAIL] {msg}")


def find_app_dir(names, r):
    apps = sorted({
        "/".join(n.split("/")[:2]) + "/"
        for n in names
        if n.startswith("Payload/") and n.count("/") >= 2 and n.split("/")[1].endswith(".app")
    })
    if not apps:
        r.fail("No Payload/<Name>.app/ found. An .ipa must be a zip whose top level is a "
               "'Payload' folder containing the .app (zip -qry App.ipa Payload).")
        return None
    if len(apps) > 1:
        r.fail(f"Multiple .app bundles in Payload/: {', '.join(apps)}")
        return None
    r.ok(f"Archive layout: {apps[0]}")
    return apps[0]


def read_plist(zf, path):
    try:
        return plistlib.loads(zf.read(path))
    except KeyError:
        return None


def mach_o_cputypes(data):
    if len(data) < 8:
        return []
    magic_be = struct.unpack(">I", data[:4])[0]
    if magic_be in (FAT_MAGIC, FAT_MAGIC_64):
        count = struct.unpack(">I", data[4:8])[0]
        size = 20 if magic_be == FAT_MAGIC else 32
        return [struct.unpack(">i", data[8 + i * size: 12 + i * size])[0] for i in range(count)]
    magic_le, cputype = struct.unpack("<Ii", data[:8])
    if magic_le == MH_MAGIC_64:
        return [cputype]
    return []


def read_profile(raw):
    # embedded.mobileprovision is a CMS-signed blob with the XML plist inside.
    start = raw.find(b"<?xml")
    end = raw.find(b"</plist>")
    if start == -1 or end == -1:
        return None
    return plistlib.loads(raw[start:end + len(b"</plist>")])


def check(ipa_path, udid, r):
    try:
        zf = zipfile.ZipFile(ipa_path)
    except (zipfile.BadZipFile, FileNotFoundError) as e:
        r.fail(f"Not a readable zip/ipa: {e}")
        return None
    names = zf.namelist()
    app = find_app_dir(names, r)
    if not app:
        return None

    info = read_plist(zf, app + "Info.plist")
    if info is None:
        r.fail(f"Missing {app}Info.plist")
        return None

    bundle_id = info.get("CFBundleIdentifier")
    short_ver = info.get("CFBundleShortVersionString")
    build_ver = info.get("CFBundleVersion")
    title = info.get("CFBundleDisplayName") or info.get("CFBundleName") or app.split("/")[1][:-4]
    for key, val in (("CFBundleIdentifier", bundle_id),
                     ("CFBundleShortVersionString", short_ver),
                     ("CFBundleVersion", build_ver)):
        (r.ok if val else r.fail)(f"{key} = {val!r}")

    platforms = info.get("CFBundleSupportedPlatforms", [])
    if info.get("DTPlatformName") == "iphonesimulator" or "iPhoneSimulator" in platforms:
        r.fail("This is a Simulator build. Archive for 'Any iOS Device (arm64)' instead.")
    else:
        r.ok(f"Platform: {info.get('DTPlatformName', 'unknown')} {platforms}")

    min_os = info.get("MinimumOSVersion")
    if min_os:
        r.ok(f"MinimumOSVersion = {min_os} (devices on older iOS will refuse the install)")

    exe = info.get("CFBundleExecutable")
    try:
        cputypes = mach_o_cputypes(zf.read(app + exe)[:4096]) if exe else []
    except KeyError:
        cputypes = None
        r.fail(f"CFBundleExecutable '{exe}' not found in the app bundle")
    if cputypes == []:
        r.fail("Executable is not a 64-bit Mach-O binary")
    elif cputypes and CPU_TYPE_ARM64 not in cputypes:
        r.fail("Executable has no arm64 slice (iOS devices need arm64)")
    elif cputypes:
        r.ok("Executable contains arm64")

    if app + "_CodeSignature/CodeResources" in names:
        r.ok("App is code-signed (_CodeSignature present)")
    else:
        r.fail("App is NOT signed (_CodeSignature/CodeResources missing)")

    try:
        profile = read_profile(zf.read(app + "embedded.mobileprovision"))
    except KeyError:
        profile = None
    if not profile:
        r.fail("embedded.mobileprovision missing or unreadable. OTA installs need an "
               "Ad Hoc, Development or Enterprise provisioning profile.")
    else:
        check_profile(profile, bundle_id, udid, r)

    for n in names:
        if n.startswith(app + "PlugIns/") and n.endswith(".appex/Info.plist") and n.count("/") == 4:
            ext_id = (read_plist(zf, n) or {}).get("CFBundleIdentifier", "")
            if bundle_id and not ext_id.startswith(bundle_id + "."):
                r.fail(f"Extension {n.split('/')[3]} has bundle ID '{ext_id}', "
                       f"which must start with '{bundle_id}.'")

    return {"bundle_id": bundle_id, "version": short_ver or build_ver, "title": title}


def check_profile(p, bundle_id, udid, r):
    devices = p.get("ProvisionedDevices")
    ents = p.get("Entitlements", {})
    if p.get("ProvisionsAllDevices"):
        kind = "Enterprise (In-House)"
    elif devices and ents.get("get-task-allow"):
        kind = "Development"
    elif devices:
        kind = "Ad Hoc"
    else:
        kind = "App Store"
    if kind == "App Store":
        r.fail("Signed with an App Store distribution profile. These can't be installed "
               "OTA. Re-export as Ad Hoc, Development or Enterprise.")
    else:
        r.ok(f"Profile '{p.get('Name')}' ({kind}), team {p.get('TeamName')}")

    exp = p.get("ExpirationDate")
    if exp:
        now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
        if exp < now:
            r.fail(f"Provisioning profile EXPIRED on {exp:%Y-%m-%d}")
        else:
            days = (exp - now).days
            (r.warn if days < 14 else r.ok)(f"Profile expires {exp:%Y-%m-%d} ({days} days)")

    app_id = ents.get("application-identifier", "")
    team_prefix = app_id.split(".", 1)[0] + "."
    pattern = app_id[len(team_prefix):] if app_id.startswith(team_prefix) else app_id
    if bundle_id and pattern:
        if fnmatch.fnmatchcase(bundle_id, pattern):
            r.ok(f"Profile App ID '{app_id}' matches bundle ID")
        else:
            r.fail(f"Profile App ID '{app_id}' does not match CFBundleIdentifier '{bundle_id}'")

    if devices:
        r.ok(f"Profile includes {len(devices)} device UDID(s)")
        if udid:
            if udid.lower() in (d.lower() for d in devices):
                r.ok(f"UDID {udid} is in the profile")
            else:
                r.fail(f"UDID {udid} is NOT in the profile. Add it in the Apple Developer "
                       "portal, regenerate the profile and re-sign.")
    elif udid and kind.startswith("Enterprise"):
        r.ok("Enterprise profile: any device can install")


def write_manifest(path, meta, ipa_url, display_image, full_size_image):
    assets = [{"kind": "software-package", "url": ipa_url}]
    if display_image:
        assets.append({"kind": "display-image", "needs-shine": False, "url": display_image})
    if full_size_image:
        assets.append({"kind": "full-size-image", "needs-shine": False, "url": full_size_image})
    manifest = {"items": [{
        "assets": assets,
        "metadata": {
            "bundle-identifier": meta["bundle_id"],
            "bundle-version": meta["version"],
            "kind": "software",
            "title": meta["title"],
        },
    }]}
    with open(path, "wb") as f:
        plistlib.dump(manifest, f, fmt=plistlib.FMT_XML, sort_keys=False)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ipa")
    ap.add_argument("--udid", help="check that this device UDID is in the provisioning profile")
    ap.add_argument("--write-manifest", metavar="PATH", help="write a manifest.plist matching the IPA")
    ap.add_argument("--ipa-url", help="HTTPS URL the IPA is served from (needed with --write-manifest)")
    ap.add_argument("--display-image", help="HTTPS URL of a 57x57 PNG")
    ap.add_argument("--full-size-image", help="HTTPS URL of a 512x512 PNG")
    args = ap.parse_args()

    r = Report()
    print(f"Checking {args.ipa}")
    meta = check(args.ipa, args.udid, r)

    if args.write_manifest:
        for name, url in (("--ipa-url", args.ipa_url), ("--display-image", args.display_image),
                          ("--full-size-image", args.full_size_image)):
            if url and not url.startswith("https://"):
                r.fail(f"{name} must be an https:// URL (got {url})")
        if not args.ipa_url:
            r.fail("--write-manifest requires --ipa-url")

    if r.failures:
        print(f"\n{r.failures} problem(s) found. iOS will refuse to install this IPA.")
        return 1

    if args.write_manifest:
        write_manifest(args.write_manifest, meta, args.ipa_url, args.display_image, args.full_size_image)
        print(f"\nWrote {args.write_manifest}")
    print("\nAll checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
