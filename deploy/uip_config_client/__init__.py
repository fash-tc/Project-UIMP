"""uip_config_client — shared library for consuming admin-api config.

Imported by every UIP service (alert-enricher, noc-escalation-bot, etc.)
that needs to read runtime config from admin-api with env fallback.
"""
from .client import ConfigClient  # noqa: F401
from .schemas import KeySchema, SEED_VERSION, SCHEMAS  # noqa: F401
