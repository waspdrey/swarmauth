from __future__ import annotations

import pytest

import swarmauth


def test_bearer_bridge_is_case_insensitive_and_keeps_token_out_of_schema() -> None:
    token = "jct-token"
    assert swarmauth.bearer_token_from_headers({"authorization": f"Bearer {token}"}) == token
    with pytest.raises(ValueError):
        swarmauth.bearer_token_from_headers({"Authorization": "Basic abc"})
    with pytest.raises(ValueError):
        swarmauth.bearer_token_from_headers({"Authorization": "Bearer one two"})


def test_oauth_bridge_validates_external_access_token_before_using_jct() -> None:
    seen: list[str] = []

    def validate(raw: str) -> str:
        seen.append(raw)
        return "validated-jct"

    with swarmauth.use_oauth_bearer_token({"Authorization": "Bearer oauth-token"}, validate=validate):
        assert seen == ["oauth-token"]
