"""GENERATED FILE. Do not edit by hand.

Regenerate with: python deploy/admin-api/build_schemas.py

Source: deploy/admin-api/seeds/config_seed.json
"""
from dataclasses import dataclass
from typing import Any, Literal


@dataclass(frozen=True)
class KeySchema:
    value_type: Literal["int", "float", "string", "bool", "json", "secret"]
    validation_rule: dict | None
    seed_version: int


SEED_VERSION = 1

SCHEMAS: dict[str, KeySchema] = {
    'ai.cluster.endpoint': KeySchema(value_type='string', validation_rule={'regex': '^https?://[a-zA-Z0-9.\\-]+(:[0-9]+)?(/.*)?$'}, seed_version=1),
    'ai.enricher.model': KeySchema(value_type='string', validation_rule=None, seed_version=1),
    'features.admin.ai_sandbox': KeySchema(value_type='bool', validation_rule=None, seed_version=1),
    'pipeline.enricher.poll_interval_sec': KeySchema(value_type='int', validation_rule={'min': 5, 'max': 3600}, seed_version=1),
}
