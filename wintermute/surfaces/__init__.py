"""Surface adapters: every layer feeds the same engine and pipeline."""
from wintermute.surfaces import (  # noqa: F401
    cloud, confluence, filesystem, git, ide, jira, postman, slack,
)

SURFACE_MODULES = {
    "filesystem": filesystem,
    "git": git,
    "ide": ide,
    "slack": slack,
    "confluence": confluence,
    "jira": jira,
    "postman": postman,
    "cloud": cloud,
}