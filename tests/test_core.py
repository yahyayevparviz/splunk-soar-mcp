import pytest

from soar_analyst_mcp.core import config, guards, modes, redaction, shaping
from soar_analyst_mcp.core.client import SoarError

from .conftest import TOKEN
from .fake_soar import load


# ---------- config ----------

def test_config_from_env(env):
    c = config.get_client()
    assert c.base == "https://soar.example.com/rest"
    assert c.session.headers["ph-auth-token"] == TOKEN
    assert c.session.verify is False


def test_config_strips_rest_suffix(env, monkeypatch):
    monkeypatch.setenv("SOAR_URL", "https://soar.example.com/rest/")
    config.reset_cache()
    assert config.get_client().base == "https://soar.example.com/rest"


def test_config_ca_bundle_path(env, monkeypatch):
    monkeypatch.setenv("SOAR_VERIFY_SSL", "/etc/ssl/ca.pem")
    config.reset_cache()
    assert config.get_client().session.verify == "/etc/ssl/ca.pem"


@pytest.mark.parametrize("var", ["SOAR_URL", "SOAR_TOKEN"])
def test_config_missing_required(env, monkeypatch, var):
    monkeypatch.delenv(var)
    config.reset_cache()
    with pytest.raises(SoarError, match=var):
        config.get_client()


# ---------- guards ----------

def test_clamp_limit():
    assert guards.clamp_limit(0) == 1
    assert guards.clamp_limit(5000) == guards.MAX_LIMIT
    assert guards.clamp_limit("abc", default=20) == 20


def test_positive_id():
    assert guards.positive_id(5) == 5
    for bad in (0, -1, "x"):
        with pytest.raises(SoarError):
            guards.positive_id(bad)


def test_status_severity_label_validation():
    assert guards.check_status("NEW") == "new"
    assert guards.check_status(None) is None
    with pytest.raises(SoarError):
        guards.check_status("deleted")
    with pytest.raises(SoarError):
        guards.check_severity("critical")
    with pytest.raises(SoarError):
        guards.check_label('edr" OR 1=1')


def test_cef_field_allowlist():
    assert guards.check_cef_field("sourceAddress") == "sourceAddress"
    with pytest.raises(SoarError):
        guards.check_cef_field("customField")
    with pytest.raises(SoarError):
        guards.check_cef_field("source__Address;drop")


def test_check_text():
    assert guards.check_text(None, required=False) is None
    with pytest.raises(SoarError):
        guards.check_text("   ")
    with pytest.raises(SoarError):
        guards.check_text("x" * 300)


def test_soar_str_escapes_quotes():
    assert guards.soar_str('a"b') == '"a\\"b"'


# ---------- shaping ----------

def test_shape_container_drops_noise():
    out = shaping.shape_container(load("container_1001.json"))
    assert out["id"] == 1001
    assert "custom_fields" not in out and "asset" not in out and "close_time" not in out


def test_trim_long_strings():
    out = shaping.shape_note({"id": 1, "content": "x" * 5000})
    assert len(out["content"]) < 2100 and "truncated" in out["content"]


def test_shape_app_run_limits_data():
    out = shaping.shape_app_run({"id": 1, "result_data": [{"status": "success",
                                                          "data": list(range(50))}]})
    assert len(out["results"][0]["data"]) == shaping.MAX_RESULT_ITEMS
    assert out["results"][0]["data_truncated"] == 40


def test_shape_asset_never_returns_configuration():
    for a in load("assets.json")["data"]:
        out = shaping.shape_asset(a)
        assert "configuration" not in out
        assert "FAKE" not in str(out)


# ---------- client errors ----------

@pytest.mark.parametrize("code,text", [(401, "401"), (403, "403"), (404, "not found"),
                                       (500, "500")])
def test_http_errors_are_clean(soar, code, text):
    soar.status_override = code
    with pytest.raises(SoarError) as e:
        config.get_client().get("container/1")
    assert text in str(e.value)
    assert TOKEN not in str(e.value)


# ---------- modes ----------

def test_mode_default_is_readonly(env):
    assert modes.current_mode() == modes.Mode.READONLY


def test_mode_invalid(env, monkeypatch):
    monkeypatch.setenv("SOAR_MCP_MODE", "god")
    with pytest.raises(SoarError, match="SOAR_MCP_MODE"):
        modes.current_mode()


def test_allowlists_parse(env, monkeypatch):
    monkeypatch.setenv("SOAR_PLAYBOOK_ALLOWLIST", " a , b,,")
    monkeypatch.setenv("SOAR_ACTION_ALLOWLIST", "IP Reputation")
    assert modes.playbook_allowlist() == {"a", "b"}
    assert modes.action_allowlist() == {"ip reputation"}


# ---------- redaction ----------

@pytest.mark.parametrize("key", ["password", "api_key", "apiKey", "client_secret", "ph-auth-token",
                                 "Authorization", "private_key", "passphrase", "credentials"])
def test_sensitive_keys_redacted(key):
    assert redaction.redact({key: "x"}) == {key: redaction.REDACTED}


@pytest.mark.parametrize("key", ["author", "fileHash", "fileHashSha256", "username", "base_url",
                                 "source_data_identifier", "playbook_run_id"])
def test_normal_keys_kept(key):
    assert redaction.redact({key: "x"}) == {key: "x"}


def test_redaction_is_recursive():
    out = redaction.redact({"a": [{"auth": {"password": "p", "user": "u"}}]})
    assert out == {"a": [{"auth": {"password": redaction.REDACTED, "user": "u"}}]}


def test_post_failed_envelope_is_error(soar):
    soar.posts.clear()
    with pytest.raises(SoarError, match="not found"):
        config.get_client().post("container/77777", {"status": "open"})
