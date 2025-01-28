from dataclasses import fields

def dataclass_from_dict(cls, **kwargs):
    return cls(**{k: v for k, v in kwargs.items() if k in fields(cls)})