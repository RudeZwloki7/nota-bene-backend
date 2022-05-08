import os
from pathlib import Path

from dotenv import load_dotenv


def get_project_root():
    return Path(__file__).parent.parent.parent


def get_env_path():
    return os.path.join(get_project_root(), '.env')


def load_env():
    load_dotenv(get_env_path())


load_env()


def get_db_url():
    url_string = "postgresql+psycopg2://{}:{}@{}:{}/{}".format(
        os.environ.get("DB_USER"),
        os.environ.get("DB_PWD"),
        os.environ.get("DB_HOST"),
        os.environ.get("DB_PORT"),
        os.environ.get("DB_NAME")
    )

    return url_string
