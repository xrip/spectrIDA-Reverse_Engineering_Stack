from spectrida import config


def test_env_override(monkeypatch):
    monkeypatch.setenv("SPECTRIDA_LLAMACPP_MODEL", "my-model")
    assert config.llamacpp_model() == "my-model"


def test_defaults():
    assert config.llamacpp_url().startswith("http")
    assert config.pipeline_workers() == 16


def test_default_config_contains_llamacpp_settings(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "config.toml")

    path = config.write_default_config()
    text = path.read_text(encoding="utf-8")

    assert "[llamacpp]" in text
    assert 'base_url = "http://localhost:8080"' in text
    assert 'model = "spectrida-re"' in text
    assert "max_tokens = 8192" in text
    assert "temperature = 0.0" in text
    assert "top_p = 0.9" in text
    assert "top_k = 1" in text
    assert 'api_key = ""' in text
    assert 'anthropic_version = "2023-06-01"' in text


def test_write_config_reloads_runtime_config(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(config, "_cfg", {"ida": {"idalib": ""}, "llamacpp": {}, "pipeline": {}})

    config.write_config(idalib="C:/IDA", model="test-model")

    assert config.idalib_dir() == "C:/IDA"
    assert config.llamacpp_model() == "test-model"


def test_onboarded_marker(tmp_path, monkeypatch):
    monkeypatch.delenv("SPECTRIDA_NO_ONBOARD", raising=False)
    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config, "_ONBOARD_MARKER", tmp_path / ".onboarded")
    assert config.onboarded() is False
    config.set_onboarded()
    assert config.onboarded() is True


def test_env_forces_skip(monkeypatch):
    monkeypatch.setenv("SPECTRIDA_NO_ONBOARD", "1")
    assert config.onboarded() is True
