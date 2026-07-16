import importlib
import pkgutil
import sys
from typing import List, Type
from cadresec.intelligence.detectors.base import BaseDetector


class DetectorRegistry:
    _detectors: List[Type[BaseDetector]] = []
    _loaded: bool = False

    @classmethod
    def load_detectors(cls) -> List[Type[BaseDetector]]:
        """Dynamically loads and returns all subclasses of BaseDetector in detectors folder."""
        if cls._loaded:
            return cls._detectors

        cls._detectors = []
        import cadresec.intelligence.detectors as detectors_pkg
        package_path = detectors_pkg.__path__

        for _, module_name, _ in pkgutil.iter_modules(package_path):
            if module_name == "base":
                continue

            full_module_name = f"cadresec.intelligence.detectors.{module_name}"
            try:
                module = importlib.import_module(full_module_name)
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, BaseDetector)
                        and attr is not BaseDetector
                    ):
                        # Hardening: Validate detector configuration prior to registering
                        if not hasattr(attr, "name") or not isinstance(attr.name, str) or not attr.name:
                            raise ValueError(f"Class {attr_name} must define a non-empty 'name' string.")
                        if not hasattr(attr, "category"):
                            raise ValueError(f"Class {attr_name} must define a 'category' attribute.")
                        if not hasattr(attr, "rules") or not isinstance(attr.rules, list):
                            raise ValueError(f"Class {attr_name} must define a 'rules' list.")
                        
                        import re
                        for i, rule in enumerate(attr.rules):
                            if not isinstance(rule, (tuple, list)) or len(rule) < 3 or len(rule) > 4:
                                raise ValueError(f"Rule {i} in {attr_name} must be a tuple/list of length 3 or 4.")
                            try:
                                re.compile(rule[1])
                            except re.error as re_err:
                                raise ValueError(f"Rule {i} in {attr_name} has invalid regex pattern '{rule[1]}': {re_err}")
                            if not isinstance(rule[2], (int, float)) or not (0.0 <= rule[2] <= 1.0):
                                raise ValueError(f"Rule {i} in {attr_name} has invalid confidence {rule[2]} (must be between 0.0 and 1.0).")
                                
                        cls._detectors.append(attr)
            except Exception as e:
                import logging
                logger = logging.getLogger("cadresec.intelligence")
                logger.warning(f"Failed to load detector module {module_name}: {e}")
                print(f"Failed to load detector module {module_name}: {e}", file=sys.stderr)

        cls._loaded = True
        return cls._detectors
