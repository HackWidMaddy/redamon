"""stop_recon removes every tool container recon spawned (drift-map #21).

SUB_CONTAINER_IMAGES is a hand list (the orchestrator does not import recon),
and it covered 7 of the 15 tool images, so a stopped scan left subfinder, tlsx,
amass, hakrawler, graphql-cop, zaproxy, wcvs and baddns siblings running. This
derives the tool images from the `*_DOCKER_IMAGE` defaults in
recon/project_settings.py and checks each is matched, then drives the clean-up
over a fake container list.
"""

import os
import re
import unittest
from unittest.mock import MagicMock

from container_manager import (
    SUB_CONTAINER_IMAGES,
    ContainerManager,
    sub_container_image_of,
)

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_RECON_SETTINGS = os.path.join(_REPO, "recon", "project_settings.py")


def _docker_image_defaults() -> dict[str, str]:
    """`'X_DOCKER_IMAGE': 'image'` entries of DEFAULT_SETTINGS, read as text so
    this needs none of recon's dependencies."""
    with open(_RECON_SETTINGS, encoding="utf-8") as f:
        text = f.read()
    return dict(re.findall(r"""['"](\w+_DOCKER_IMAGE)['"]\s*:\s*['"]([^'"]+)['"]""", text))


def _container(image: str, status: str = "running") -> MagicMock:
    c = MagicMock()
    c.name = f"c-{image}"
    c.status = status
    c.image.tags = [image]
    c.attrs = {"Config": {"Image": image}}
    return c


class TestEveryToolImageIsCleanedUp(unittest.TestCase):
    def setUp(self):
        if not os.path.isfile(_RECON_SETTINGS):
            self.skipTest("recon/project_settings.py is not in this checkout")

    def test_defaults_are_parsed(self):
        # A broken parser must fail here, not make the coverage test pass vacuously.
        self.assertGreaterEqual(len(_docker_image_defaults()), 10)

    def test_every_docker_image_default_is_a_sub_container_image(self):
        missing = sorted(
            f"{key}={img}" for key, img in _docker_image_defaults().items()
            if sub_container_image_of([img]) is None
        )
        self.assertEqual(
            missing, [],
            "stop_recon would leave these tool containers behind; add the image "
            "(without its tag) to SUB_CONTAINER_IMAGES in container_manager.py",
        )


class TestMatchStaysNarrow(unittest.TestCase):
    def test_no_entry_matches_a_non_tool_image(self):
        for image in (
            "redamon-supply-chain:latest",
            "redamon-supply-chain-analyzer:latest",
            "redamon-recon:latest",
            "redamon-agent:latest",
            "redamon-trufflehog:latest",
            "alpine:latest",
        ):
            with self.subTest(image=image):
                self.assertIsNone(sub_container_image_of([image]))

    def test_entries_carry_no_tag(self):
        tagged = [i for i in SUB_CONTAINER_IMAGES if ":" in i.rsplit("/", 1)[-1]]
        self.assertEqual(tagged, [], "a tag in an entry stops it matching other tags")


class TestCleanupSubContainers(unittest.TestCase):
    def test_removes_tool_containers_and_keeps_the_rest(self):
        tools = [
            _container("projectdiscovery/subfinder:latest"),
            _container("redamon-wcvs:latest", status="paused"),
            _container("redamon-baddns:latest", status="exited"),
            _container("ghcr.io/zaproxy/zaproxy:stable"),
        ]
        others = [_container("redamon-supply-chain:latest"), _container("alpine:latest")]
        m = ContainerManager.__new__(ContainerManager)
        m.client = MagicMock()
        m.client.containers.list.return_value = tools + others

        self.assertEqual(m._cleanup_sub_containers(), len(tools))
        for c in tools:
            c.remove.assert_called_once_with(force=True)
        tools[1].unpause.assert_called_once()
        tools[2].stop.assert_not_called()
        for c in others:
            c.remove.assert_not_called()
            c.stop.assert_not_called()


if __name__ == "__main__":
    unittest.main()
