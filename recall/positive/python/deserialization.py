import pickle
import yaml


def load_object(data):
    # AST-DESER-001: CRITICAL — pickle.loads() deserializes arbitrary objects
    return pickle.loads(data)


def load_config(content):
    # AST-DESER-004: HIGH — yaml.load() without Loader= argument
    return yaml.load(content)
