"""Benchmark: measures what SafetyWebbing finds against targets whose weaknesses are known.

Ground truth lives in per-target manifests (manifest.py), kept OUTSIDE anything an agent is
told about. Results are produced by a CLI and committed; the web page only reads them
(see benchmark/PROTOCOL.md).
"""
