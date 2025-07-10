import pkgutil
import importlib
from GormikuIps import SimpleIDSIPS

ids = SimpleIDSIPS()

# auto‐discover + register everything in rules/
for finder, modname, ispkg in pkgutil.iter_modules(['rules']):
    module = importlib.import_module(f"rules.{modname}")

    # register regex patterns
    for pattern, location, ignore_case in getattr(module, "REQUEST_PATTERNS", []):
        ids.addRequestPattern(pattern, location, ignore_case)
    for pattern, location, ignore_case in getattr(module, "RESPONSE_PATTERNS", []):
        ids.addResponsePattern(pattern, location, ignore_case)

    # register function‐based rules
    for func in getattr(module, "REQUEST_FUNCTIONS", []):
        ids.addRequestFunction(func)
    for func in getattr(module, "RESPONSE_FUNCTIONS", []):
        ids.addResponseFunction(func)

addons = [ids]
