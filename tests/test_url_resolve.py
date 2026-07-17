"""Power Apps / Dynamics URL parsing (disambiguation by pasted URL)."""

from __future__ import annotations

from impactiq.agents.url_resolve import find_url_in_text, parse_powerapps_url


def test_model_driven_record_url():
    url = (
        "https://contoso.crm.dynamics.com/main.aspx?appid=abc"
        "&pagetype=entityrecord&etn=new_customerrequest"
        "&id=3f2504e0-4f89-41d3-9a0c-0305e82c3301"
    )
    p = parse_powerapps_url(url)
    assert p["entity_logical"] == "new_customerrequest"
    assert p["record_id"] == "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
    assert p["pagetype"] == "entityrecord"
    assert p["host"] == "contoso.crm.dynamics.com"


def test_view_url():
    url = (
        "https://contoso.crm.dynamics.com/main.aspx?pagetype=entitylist"
        "&etn=account&viewid=00000000-0000-0000-0000-000000000abc&viewType=1039"
    )
    p = parse_powerapps_url(url)
    assert p["entity_logical"] == "account"
    assert p["view_id"] == "00000000-0000-0000-0000-000000000abc"


def test_maker_portal_table_url():
    url = (
        "https://make.powerapps.com/environments/Default-123/entities/"
        "new_admintask/columns"
    )
    p = parse_powerapps_url(url)
    assert p["entity_logical"] == "new_admintask"
    assert p["environment_id"] == "Default-123"


def test_garbage_url_returns_empty_ish():
    p = parse_powerapps_url("not a url")
    assert "entity_logical" not in p


def test_find_url_in_text():
    text = "look at https://contoso.crm.dynamics.com/main.aspx?etn=account please"
    assert find_url_in_text(text).startswith("https://contoso.crm.dynamics.com")
    assert find_url_in_text("no link here") is None


def test_invalid_guid_is_dropped():
    url = "https://x.crm.dynamics.com/main.aspx?etn=account&id=not-a-guid"
    p = parse_powerapps_url(url)
    assert p["entity_logical"] == "account"
    assert "record_id" not in p
