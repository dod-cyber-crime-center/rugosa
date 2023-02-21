"""
Runs tests and other routines.

Usage:
  1. Install "nox"
  2. Run "nox" or "nox -s test"
"""
import os

import nox


def _install_local_deps(session):
    """Install local dc3 dependencies."""
    for path in ["../dc3_pyhidra_github", "../dc3_dragodis_github"]:
        if os.path.exists(path):
            session.install(path)


@nox.session(python="3.8")
def test(session):
    """Run pytests"""
    _install_local_deps(session)
    session.install("-e", ".[testing]")
    session.run("pytest")


@nox.session(python="3.8")
def build(session):
    """Build source and wheel distribution"""
    session.run("python", "setup.py", "sdist")
    session.run("python", "setup.py", "bdist_wheel")


@nox.session(python=False)
def release_patch(session):
    """Generate release patch"""
    session.run("mkdir", "-p", "dist", external=True)
    with open("./dist/updates.patch", "w") as out:
        session.run(
            "git", "format-patch", "--stdout", "main",
            external=True,
            stdout=out
        )
