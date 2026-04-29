
from pathlib import Path

import platformdirs
from dynaconf import Dynaconf

default_config = Path(__file__).parent / "settings.toml"
user_config = platformdirs.user_config_path("rugosa", appauthor="dc3") / "settings.toml"
local_config = Path("rugosa.toml")


settings = Dynaconf(
    envvar_prefix="RUGOSA",
    load_dotenv=True,
    merge_enabled=True,
    settings_files=[
        default_config,
        user_config,
        local_config,
    ],
)
