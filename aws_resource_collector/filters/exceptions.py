class FilterError(Exception):
    """Base class for filter exceptions"""
    pass

class InvalidTagFormatError(FilterError):
    """Raised when tag format is invalid"""
    pass

class InvalidResourceTypeError(FilterError):
    """Raised when resource type format is invalid"""
    pass 