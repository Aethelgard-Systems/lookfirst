"""Torwächter – a gatekeeper between AI agents and tools.

Every *writing* tool call passes: preview → human confirmation → execution → read-back → signed, hash-chained audit log.
Reading calls pass through unchanged. Implemented as an MCP proxy (stdio or Streamable HTTP) in front of one or more
upstream MCP servers. Standalone: no imports from any other project.
"""
__version__ = "0.1.0"
