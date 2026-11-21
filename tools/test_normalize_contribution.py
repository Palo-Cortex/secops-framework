"""normalize_contribution: export suffixes come off names, and no name can make the pattern hang."""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from normalize_contribution import NAME_SUFFIX_RE  # noqa: E402

# Long enough that the old pattern backtracks for minutes; the new one is instant.
REPEATS = 40
SECONDS = 5


def _strip(name):
    return NAME_SUFFIX_RE.sub("", name).strip()


def test_export_suffixes_come_off_in_any_case_and_combination():
    assert _strip("EP_IR_NIST_copy") == "EP_IR_NIST"
    assert _strip("EP_IR_NIST_Copy_export") == "EP_IR_NIST"
    assert _strip("SOCFWConfig_BAK ") == "SOCFWConfig"
    assert _strip("Foundation_old_Old") == "Foundation"


def test_version_suffixes_and_plain_names_are_kept():
    assert _strip("SOCFrameworkActions_V3") == "SOCFrameworkActions_V3"
    assert _strip("copy_of_playbook") == "copy_of_playbook"
    assert _strip("Playbook") == "Playbook"


def test_a_long_run_of_suffixes_that_does_not_end_the_name_finishes_quickly():
    name = "Playbook" + "_bak" * REPEATS + "!"
    code = (
        f"import sys; sys.path.insert(0, {HERE!r}); "
        "from normalize_contribution import NAME_SUFFIX_RE; "
        f"NAME_SUFFIX_RE.search({name!r})"
    )
    try:
        subprocess.run([sys.executable, "-c", code], timeout=SECONDS, check=True)
    except subprocess.TimeoutExpired:
        raise AssertionError(f"the suffix pattern took over {SECONDS}s on {REPEATS} repeats") from None
