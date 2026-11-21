"""normalize_ruleid_adopted: only a script's own files are script metadata, never its test data."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from normalize_ruleid_adopted import _is_script_json, _is_script_yaml, normalize_scripts_json  # noqa: E402


def test_a_script_json_is_script_metadata():
    assert _is_script_json("Packs/p/Scripts/MyScript/MyScript.json")


def test_a_script_yaml_is_script_metadata():
    assert _is_script_yaml("Packs/p/Scripts/MyScript/MyScript.yml")


def test_json_in_test_data_is_not_script_metadata():
    assert not _is_script_json("Packs/p/Scripts/MyScript/test_data/golden.json")


def test_yaml_in_test_data_is_not_script_metadata():
    assert not _is_script_yaml("Packs/p/Scripts/MyScript/test_data/fixture.yml")


def test_normalizing_leaves_test_data_untouched(tmp_path):
    fixture = tmp_path / "Packs" / "p" / "Scripts" / "MyScript" / "test_data" / "golden.json"
    fixture.parent.mkdir(parents=True)
    fixture.write_text('{"routing": {}}')
    normalize_scripts_json(str(tmp_path), dry_run=False)
    assert fixture.read_text() == '{"routing": {}}'
