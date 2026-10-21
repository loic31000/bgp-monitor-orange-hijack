"""Sources de données publiques et passives : RIPEstat, RIS Live, IRR (whois)."""


class SourceError(Exception):
    """Une source n'a pas pu fournir de données exploitables."""
