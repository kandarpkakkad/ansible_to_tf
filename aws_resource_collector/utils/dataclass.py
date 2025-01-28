from dataclasses import fields
from typing import Type, TypeVar

T = TypeVar('T')


def dataclass_from_dict(cls: Type[T], **kwargs) -> T:
    try:
        field_types = cls.__annotations__
        return cls(**{f: dataclass_from_dict(field_types[f], kwargs[f]) for f in kwargs if f in field_types})
    except AttributeError as e:
        if isinstance(kwargs, (tuple, list)):
            return [dataclass_from_dict(cls.__args__[0], i) for i in kwargs]
        return kwargs
