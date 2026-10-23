from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    apns_team_id: str = ""
    apns_key_id: str = ""
    apns_bundle_id: str = ""
    apns_private_key_path: str = ""
    apns_private_key: str = ""
    database_path: str = "/data/apns.db"
    api_key: str = ""
    apns_timeout_seconds: float = 10.0
    log_level: str = "INFO"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    def signing_key(self) -> str:
        if self.apns_private_key:
            return self.apns_private_key.replace("\\n", "\n")
        if self.apns_private_key_path:
            with open(self.apns_private_key_path, encoding="utf-8") as key_file:
                return key_file.read()
        raise RuntimeError("APNS_PRIVATE_KEY or APNS_PRIVATE_KEY_PATH must be configured")


@lru_cache
def get_settings() -> Settings:
    return Settings()

