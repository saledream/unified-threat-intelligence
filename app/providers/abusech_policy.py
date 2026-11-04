"""Separate personal community access from licensed business authorization."""
import os


def authorized() -> bool:
    mode=os.getenv('ABUSECH_USAGE_MODE','commercial').strip().lower()
    return mode=='personal' or (mode=='commercial' and os.getenv('ABUSECH_COMMERCIAL_AUTHORIZED','').lower() in {'true','1','yes'})
