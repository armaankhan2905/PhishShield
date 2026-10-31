"""The "Get the extension" page's server side: version info and the downloadable zip."""
import io
import json
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient

from src.pipeline.demo import app

client = TestClient(app)
MANIFEST = json.loads((Path(__file__).resolve().parents[1] / "extension" / "manifest.json").read_text(encoding="utf-8"))


def test_extension_info_matches_manifest(monkeypatch):
    info = client.get("/api/extension").json()
    assert info["version"] == MANIFEST["version"] and info["store_url"] is None
    monkeypatch.setenv("PHISHSHIELD_EXTENSION_STORE_URL", "https://chromewebstore.google.com/detail/phishshield/abc")
    assert client.get("/api/extension").json()["store_url"].startswith("https://chromewebstore.google.com/")
    monkeypatch.setenv("PHISHSHIELD_EXTENSION_STORE_URL", "https://evil.example/x")
    assert client.get("/api/extension").json()["store_url"] is None  # only a real Web Store link becomes a button


def test_zip_is_ready_for_load_unpacked():
    r = client.get("/download/phishshield-extension.zip")
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    assert f"phishshield-extension-{MANIFEST['version']}.zip" in r.headers["content-disposition"]
    names = zipfile.ZipFile(io.BytesIO(r.content)).namelist()
    assert all(n.startswith("phishshield-extension/") for n in names)
    manifest = json.loads(zipfile.ZipFile(io.BytesIO(r.content)).read("phishshield-extension/manifest.json"))
    referenced = [manifest["background"]["service_worker"], manifest["action"]["default_popup"], manifest["options_page"],
                  *manifest["icons"].values(), *(js for cs in manifest["content_scripts"] for js in cs["js"])]
    assert all("phishshield-extension/" + p in names for p in referenced)
    assert not any("/dev/" in n or "/test/" in n for n in names)


def test_extension_page_is_served():
    r = client.get("/extension")
    assert r.status_code == 200 and "Get the PhishShield extension" in r.text
