"""``pktcap plugins``: what is loaded, and the filter keys that exist."""

from __future__ import annotations

import json
import pathlib
from typing import List, Optional

from .._dissectors import DissectorRegistry
from .._frame_filter import frame_filter_keys
from .._layers import BUILTIN_LAYERS
from .._plugins._config import capture_config_path
from ._common import Loading

__all__ = ["Plugins"]


class Plugins(Loading):
    """Load the plugins as the other commands would and show them: the configuration file, each plugin with what it registered, and every filter key."""

    _parsername_ = "plugins"

    layer: Optional[str] = None
    "Print the filter keys of this layer, one per line, and nothing else. Omitted: the whole summary"
    ("--layer",)

    json_out: bool = False
    "Print one JSON object with configuration, plugins and keys. Omitted: text"
    ("--json",)

    def _text(
        self, registry: DissectorRegistry, path: Optional[pathlib.Path]
    ) -> List[str]:
        keys = frame_filter_keys(registry)
        if path is None:
            lines = ["configuration: none"]
        else:
            absent = "" if path.is_file() else " (absent)"
            lines = ["configuration: %s%s" % (path, absent)]
        if self.loaded:
            lines.append(
                "plugins: %d from %s" % (len(self.loaded), self.loaded[0].source)
            )
        else:
            lines.append("plugins: none")
        for plugin in self.loaded:
            parts = []
            if plugin.selectors:
                parts.append(", ".join("%s %d" % pair for pair in plugin.selectors))
            if plugin.layers:
                parts.append("layer %s" % ", ".join(plugin.layers))
            lines.append(
                "  %s: %s" % (plugin.name, "; ".join(parts) or "nothing registered")
            )
        lines.append("keys: %s" % ", ".join(key for key in keys if "." not in key))
        lines.append(
            "layers: %s"
            % ", ".join(sorted(set(BUILTIN_LAYERS) | set(registry.layers())))
        )
        return lines

    def __call__(self) -> Optional[int]:
        path = capture_config_path(self.config)
        configuration = None if path is None else str(path)
        registry = self._registry()
        keys = frame_filter_keys(registry)
        if self.layer is not None:
            wanted = [key for key in keys if key.startswith(self.layer.lower() + ".")]
            if not wanted:
                raise ValueError(
                    "no layer named %r: the layers are %s"
                    % (
                        self.layer,
                        ", ".join(sorted(set(BUILTIN_LAYERS) | set(registry.layers()))),
                    )
                )
            print("\n".join(wanted))
        elif self.json_out:
            print(
                json.dumps(
                    {
                        "configuration": configuration,
                        "plugins": [
                            {
                                "name": plugin.name,
                                "source": plugin.source,
                                "selectors": [list(pair) for pair in plugin.selectors],
                                "layers": list(plugin.layers),
                            }
                            for plugin in self.loaded
                        ],
                        "keys": list(keys),
                    }
                )
            )
        else:
            print("\n".join(self._text(registry, path)))
        return None
