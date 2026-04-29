"""
Helper script to manage configuration.
"""

import argparse
import os
import subprocess
import sys

from . import user_config, default_config, local_config


def _create_config(path):
    print(f"Writing: {path.absolute()}", file=sys.stderr)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(default_config.read_text())


def main():
    parser = argparse.ArgumentParser("rugosa.config", description="Initializes and opens settings.toml in user directory.")
    subparsers = parser.add_subparsers(dest="command")

    parser_init = subparsers.add_parser("create", help="Creates a settings file in user directory or current directory.")
    parser_init.add_argument("-o", "--overwrite", action="store_true", help="Overwrite existing settings")
    parser_init.add_argument(
        "-l", "--local",
        action="store_true",
        help=f"Create local settings file instead of one at {user_config}"
    )

    parser_edit = subparsers.add_parser("edit", help="Opens settings.toml for editing.")
    parser_edit.add_argument(
        "-l", "--local",
        action="store_true",
        help=f"Open local settings file instead of one at {user_config}"
    )

    parser_list = subparsers.add_parser("list", help="Lists currently applied settings.")

    args = parser.parse_args()

    if args.command == "create":
        path = local_config if args.local else user_config
        if path.exists() and not args.overwrite:
            sys.exit("Error: settings file already exists and --overwrite flag was not specified.")
        _create_config(path)

    elif args.command == "list":
        subprocess.run(["dynaconf", "-i", "rugosa.config.settings", "list"])

    elif args.command == "edit":
        path = local_config if args.local else user_config
        if not path.exists():
            _create_config(path)
        print(f"Opening {path.absolute()} for editing...")
        if sys.platform == "win32":
            try:
                os.startfile(path, "edit")
            except WindowsError:
                os.startfile(path)
        else:
            opener = "open" if sys.platform == "darwin" else "xdg-open"
            subprocess.call([opener, path])

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
