import pbr.version

version_info = pbr.version.VersionInfo('python-neutrinoclient')

try:
    __version__ = version_info.version_string()
except Exception:
    __version__ = None
