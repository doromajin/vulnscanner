"""Negative: safe YAML loading — safe_load variant must never fire.

yaml.safe_load() is not in the dangerous-function list (_YAML_LOAD_FUNCS) and
its name does not match the DESER-002 regex (yaml\\.(?:load|unsafe_load)).
"""
import yaml


def load_config(stream) -> dict:
    return yaml.safe_load(stream)


def load_multi(stream) -> list:
    return list(yaml.safe_load_all(stream))


def parse_inline(text: str) -> object:
    return yaml.safe_load(text)
