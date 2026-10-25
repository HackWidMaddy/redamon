"""Broker/recon image-allowlist parity (recon -> broker direction).

Recon and partial recon spawn every scan tool as a sibling container through
the broker's filtered socket (container_manager.py points their DOCKER_HOST at
it), and the broker refuses to pull or create any image missing from its
allowlist. The two lists live in separate services, so this derives the recon
side from what recon actually runs, the `*_DOCKER_IMAGE` defaults and the
images recon/entrypoint.sh pre-pulls, and asserts the broker's shipped list
allows every one of them. Locally built `redamon-*` images are included: they
go through the broker like any other, and exempting them is how the WCVS image
was refused at run time with this test green (drift-map #2, #29).

Run: ./redamon.sh test unit (section docker_broker)
"""

import os
import re
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(os.path.dirname(_HERE))
sys.path.insert(0, _HERE)
sys.path.insert(0, _REPO)

import broker  # noqa: E402

if not os.path.isfile(os.path.join(_REPO, "recon", "project_settings.py")):
    pytest.skip("recon/ is not in this checkout; nothing to compare the broker with",
                allow_module_level=True)

from recon.project_settings import ALLOWED_TOOL_IMAGES, DEFAULT_SETTINGS  # noqa: E402

_ENTRYPOINT = os.path.join(_REPO, "recon", "entrypoint.sh")

# Images recon names but never spawns through the broker socket, each with the
# reason. Empty today: recon reaches Docker only through the broker. An entry
# here is a claim about container_manager.py, so name the spawn path.
RECON_IMAGES_OUTSIDE_BROKER: dict[str, str] = {}


def _broker_allows(image: str) -> bool:
    """Match against the SHIPPED list, not ALLOWED_IMAGES: the env extras
    (DOCKER_BROKER_ALLOWED_IMAGES) are an operator's, and must not make a
    shipped tool pass here."""
    shipped = {broker._canonical_image(i) for i in broker._DEFAULT_ALLOWED_IMAGES}
    return broker._canonical_image(image) in shipped


def _docker_image_defaults() -> dict[str, str]:
    return {
        k: v for k, v in DEFAULT_SETTINGS.items()
        if k.endswith("_DOCKER_IMAGE") and isinstance(v, str) and v
    }


def _entrypoint_images() -> list[str]:
    """The quoted entries of the IMAGES=( ... ) bash array, comments skipped."""
    with open(_ENTRYPOINT, encoding="utf-8") as f:
        text = f.read()
    block = re.search(r"^IMAGES=\((.*?)^\)", text, re.S | re.M)
    assert block, f"no IMAGES=( ... ) array in {_ENTRYPOINT}"
    images = []
    for line in block.group(1).splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            images.extend(re.findall(r'"([^"]+)"', line))
    return images


def test_sources_are_parsed():
    # A broken parser must fail here, not make the parity tests pass vacuously.
    assert len(_docker_image_defaults()) >= 10
    assert len(_entrypoint_images()) >= 10


def test_every_docker_image_default_is_broker_allowlisted():
    missing = sorted(
        f"{key}={img}" for key, img in _docker_image_defaults().items()
        if img not in RECON_IMAGES_OUTSIDE_BROKER and not _broker_allows(img)
    )
    assert not missing, (
        "recon spawns these through the broker but services/docker_broker/broker.py "
        f"_DEFAULT_ALLOWED_IMAGES refuses them: {missing}"
    )


def test_every_entrypoint_prepull_image_is_broker_allowlisted():
    missing = sorted(
        img for img in _entrypoint_images()
        if img not in RECON_IMAGES_OUTSIDE_BROKER and not _broker_allows(img)
    )
    assert not missing, (
        "recon/entrypoint.sh pulls these through the broker but "
        f"_DEFAULT_ALLOWED_IMAGES refuses them: {missing}"
    )


def test_outside_broker_entries_are_live_and_explained():
    recon_images = set(_docker_image_defaults().values()) | set(_entrypoint_images())
    stale = sorted(set(RECON_IMAGES_OUTSIDE_BROKER) - recon_images)
    assert not stale, f"RECON_IMAGES_OUTSIDE_BROKER names images recon no longer uses: {stale}"
    unexplained = sorted(i for i, why in RECON_IMAGES_OUTSIDE_BROKER.items() if not why.strip())
    assert not unexplained, f"RECON_IMAGES_OUTSIDE_BROKER entries need a reason: {unexplained}"


def test_wcvs_and_tlsx_specifically_are_on_both():
    for img in ("projectdiscovery/tlsx:latest", "redamon-wcvs:latest"):
        assert img in ALLOWED_TOOL_IMAGES
        assert _broker_allows(img)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
