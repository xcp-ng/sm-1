import typing
from typing import *

if not hasattr(typing, 'override'):
    def override(method): # type: ignore
        try:
            # Set internal attr `__override__` like described in PEP 698.
            method.__override__ = True
        except (AttributeError, TypeError):
            pass
        return method

if not hasattr(typing, 'Never'):
    Never = None # type: ignore
