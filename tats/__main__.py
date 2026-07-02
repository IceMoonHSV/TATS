"""Entry point for ``python -m tats``.

Delegates to :func:`tats.main_cli` so the in-checkout invocation
matches the installed-console-script behaviour.
"""
from . import main_cli

if __name__ == "__main__":
    main_cli()
