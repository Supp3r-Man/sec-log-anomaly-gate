"""Detector configuration: a JSON object {rule: {param: number}}. The default is the output of
`python -m seclog tune` on the dev split (seed DEV_SEED); it never saw the test split."""
import json
import math
from pathlib import Path

from .detect import RULES

DEV_SEED, TEST_SEED = 11, 22
DEFAULT_PATH = Path(__file__).with_name("default_config.json")
_INT_PARAMS = ("n", "k", "min_count", "min_hist", "seen_ok")


class ConfigError(Exception):
    pass


def validate(cfg):
    if not isinstance(cfg, dict) or not cfg:
        raise ConfigError("config must be a non-empty JSON object")
    for name, p in cfg.items():
        if name not in RULES:
            raise ConfigError(f"unknown rule {name!r}")
        keys = set(RULES[name]["grid"])
        if not isinstance(p, dict) or set(p) != keys:
            raise ConfigError(f"{name}: params must be exactly {sorted(keys)}")
        for k, v in p.items():
            if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v < 0:
                raise ConfigError(f"{name}.{k}: must be a finite number >= 0")
            if k in _INT_PARAMS and v < 1:
                raise ConfigError(f"{name}.{k}: must be >= 1")
            if k == "ratio" and not 0 < v <= 1:
                raise ConfigError(f"{name}.ratio: must be in (0, 1]")
        if name == "offhours_rule" and p["end"] <= p["start"]:
            raise ConfigError("offhours_rule: end must be greater than start")
    return cfg


def load_config(path=None):
    p = Path(path) if path else DEFAULT_PATH
    try:
        cfg = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ConfigError(f"cannot read config {p}: {e}") from e
    return validate(cfg)
