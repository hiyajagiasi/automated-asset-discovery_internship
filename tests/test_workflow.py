from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from main import build_project_structure


def test_build_project_structure_creates_expected_directories(tmp_path):
    root = tmp_path
    result = build_project_structure(root)

    assert result["reports"] == root / "reports"
    assert result["output"] == root / "output"
    assert result["logs"] == root / "logs"
    assert (root / "reports").exists()
    assert (root / "output").exists()
    assert (root / "logs").exists()
