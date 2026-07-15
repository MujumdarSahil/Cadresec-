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
                        cls._detectors.append(attr)
            except Exception as e:
                print(f"Failed to load detector module {module_name}: {e}", file=sys.stderr)

        cls._loaded = True
        return cls._detectors
