"""
test_roles.py - what each kind of user can and cannot do: trader, officer
of one State, officer of another State, admin.
"""

from conftest import issue, issue_code, login, post, q, status_of

FIRM = "Sharma Weighbridge Co. (sample)"


def apply_as_trader(c, serial="WB-9001", state="TN", place="Chennai"):
    """trader1 asks for a verification visit. Returns the response."""
    login(c, "trader1")
    return post(c, "/apply", {"serial_number": serial, "instrument_type": "Weighbridge",
                              "state_code": state, "jurisdiction": place,
                              "address": "12 Market Road (sample)", "note": "Gate 2"})


def reference(c):
    """The newest application's reference."""
    return q("SELECT reference FROM applications ORDER BY id DESC LIMIT 1")[0][0]


# ---------------------------------------------------------------- trader
def test_trader_lands_on_their_own_page_not_a_refusal(app_client):
    r = login(app_client, "trader1")
    assert r.status_code == 302 and r.headers["Location"].endswith("/my")
    assert app_client.get("/my").status_code == 200


def test_trader_sees_only_their_firms_certificates(app_client):
    login(app_client)
    mine = issue_code(app_client, owner=FIRM)
    other = issue_code(app_client, serial="X-2", owner="Another Firm (sample)")
    login(app_client, "trader1")
    page = app_client.get("/my").get_data(as_text=True)
    assert mine in page and other not in page
    assert app_client.get(f"/certificate/{mine}").status_code == 200
    assert app_client.get(f"/certificate/{other}").status_code == 403


def test_trader_is_told_when_an_instrument_needs_re_verification(app_client):
    login(app_client)
    issue_code(app_client, owner=FIRM, days_ago=400)
    login(app_client, "trader1")
    page = app_client.get("/my").get_data(as_text=True)
    assert "need" in page and "Request re-verification" in page


def test_trader_request_reaches_the_officer_of_that_state_only(app_client):
    r = apply_as_trader(app_client)
    assert r.status_code == 302
    ref = reference(app_client)
    login(app_client)                                   # lab1, Tamil Nadu
    assert ref in app_client.get("/dashboard").get_data(as_text=True)
    login(app_client, "mz1")                            # Mizoram
    assert ref not in app_client.get("/dashboard").get_data(as_text=True)


def test_issuing_from_a_request_fills_the_form_and_closes_the_request(app_client):
    apply_as_trader(app_client)
    ref = reference(app_client)
    login(app_client)
    form = app_client.get(f"/issue?application={ref}").get_data(as_text=True)
    assert 'value="WB-9001"' in form and FIRM in form and ref in form
    r = post(app_client, "/submit", {"serial_number": "WB-9001", "owner_name": FIRM,
                                     "instrument_type": "Weighbridge", "verification_date": __import__("clock").today().isoformat(),
                                     "state_code": "TN", "jurisdiction": "Chennai", "application": ref})
    assert r.status_code == 302
    (status, code), = q("SELECT status, certificate_code FROM applications WHERE reference = :r", r=ref)
    assert status == "issued" and code.startswith("SD-")
    login(app_client, "trader1")
    assert code in app_client.get("/my").get_data(as_text=True)


def test_officer_of_another_state_cannot_use_or_decline_a_request(app_client):
    apply_as_trader(app_client)
    ref = reference(app_client)
    login(app_client, "mz1")
    assert ref not in app_client.get(f"/issue?application={ref}").get_data(as_text=True)
    assert post(app_client, f"/applications/{ref}/decline", {"reason": "Not ours at all"}).status_code == 403


def test_declining_needs_a_reason_and_the_trader_sees_it(app_client):
    apply_as_trader(app_client)
    ref = reference(app_client)
    login(app_client)
    post(app_client, f"/applications/{ref}/decline", {"reason": ""})
    assert q("SELECT status FROM applications")[0][0] == "submitted"
    post(app_client, f"/applications/{ref}/decline", {"reason": "Instrument not installed yet"})
    login(app_client, "trader1")
    page = app_client.get("/my").get_data(as_text=True)
    assert "Declined" in page and "Instrument not installed yet" in page


def test_request_form_checks_every_field(app_client):
    login(app_client, "trader1")
    r = post(app_client, "/apply", {"serial_number": "", "instrument_type": "Rocket", "state_code": "TN",
                                    "jurisdiction": "Nowhere", "address": ""})
    page = r.get_data(as_text=True)
    assert r.status_code == 400 and "Serial number is required" in page and "Choose the district" in page
    assert q("SELECT COUNT(*) FROM applications")[0][0] == 0


def test_officers_cannot_send_requests_and_traders_cannot_issue(app_client):
    login(app_client)
    assert app_client.get("/apply").status_code == 403
    login(app_client, "trader1")
    assert issue(app_client).status_code == 403


# ---------------------------------------------------------------- State boundaries
def test_officer_cannot_issue_for_another_state(app_client):
    login(app_client)                                   # Tamil Nadu
    r = issue(app_client, state="MZ", place="Aizawl")
    assert r.status_code == 400 and b"LM-308" in r.data


def test_officer_form_only_offers_their_own_state(app_client):
    login(app_client, "mz1")
    page = app_client.get("/issue?state_code=TN").get_data(as_text=True)
    assert "Aizawl" in page and "Chennai" not in page


def test_admin_can_issue_for_any_state(app_client):
    login(app_client, "admin1")
    code = issue_code(app_client, state="MZ", place="Aizawl")
    assert status_of(app_client, code)[0] == "VALID"


def test_officer_cannot_revoke_another_states_certificate(app_client):
    login(app_client, "mz1")
    code = issue_code(app_client, state="MZ", place="Aizawl")
    login(app_client, "district1")                      # Tamil Nadu
    assert post(app_client, f"/revoke/{code}", {"reason": "Not my State"}).status_code == 403
    assert status_of(app_client, code)[0] == "VALID"


def test_due_lists_show_only_the_officers_state(app_client):
    login(app_client, "admin1")
    tn = issue_code(app_client, serial="TN-1", days_ago=400)
    mz = issue_code(app_client, serial="MZ-1", days_ago=400, state="MZ", place="Aizawl")
    login(app_client, "mz1")
    page = app_client.get("/reminders").get_data(as_text=True)
    assert mz in page and tn not in page
    login(app_client, "admin1")
    page = app_client.get("/reminders").get_data(as_text=True)
    assert mz in page and tn in page


# ---------------------------------------------------------------- team accounts
def test_each_team_member_has_an_officer_in_a_different_state(app_client):
    rows = q("SELECT username, full_name, state_code FROM users WHERE full_name LIKE '%(demo officer)'")
    assert len(rows) == 6 and len({state for _, _, state in rows}) == 6
    assert all("(demo officer)" in name for _, name, _ in rows)


def test_team_officer_can_log_in_and_issue_in_their_state(app_client):
    login(app_client, "krishna")                        # Gujarat
    code = issue_code(app_client, state="GJ", place="Ahmedabad")
    assert status_of(app_client, code)[0] == "VALID"


def test_every_state_has_districts_and_an_honest_settings_note():
    import config
    assert len(config.STATES) >= 8
    for cfg in config.STATES.values():
        assert cfg.get("jurisdictions"), cfg["state_code"]
        assert "illustrative" in cfg.get("settings_note", ""), cfg["state_code"]


# ---------------------------------------------------------------- public reports
def test_report_goes_to_the_state_of_the_certificate_it_names(app_client):
    login(app_client, "mz1")
    code = issue_code(app_client, state="MZ", place="Aizawl")
    post(app_client, "/logout")
    post(app_client, "/report", {"serial_number": code, "description": "Seal on this scale is broken (sample)"})
    assert q("SELECT state_code FROM reports") == [("MZ",)]
    login(app_client)                                   # Tamil Nadu officer does not see it
    assert "Seal on this scale" not in app_client.get("/dashboard").get_data(as_text=True)
    login(app_client, "mz1")
    assert "Seal on this scale" in app_client.get("/dashboard").get_data(as_text=True)


def test_officer_closes_a_report_with_an_outcome(app_client):
    post(app_client, "/report", {"serial_number": "", "state_code": "TN", "description": "Pump at Guindy looks tampered (sample)"})
    (rid,), = q("SELECT id FROM reports")
    login(app_client)
    post(app_client, f"/reports/{rid}/close", {"outcome": ""})
    assert q("SELECT status FROM reports") == [("open",)]
    post(app_client, f"/reports/{rid}/close", {"outcome": "Inspected; seal intact (sample)"})
    assert q("SELECT status, outcome FROM reports") == [("closed", "Inspected; seal intact (sample)")]
    assert "Pump at Guindy" not in app_client.get("/dashboard").get_data(as_text=True)


def test_officer_cannot_close_another_states_report(app_client):
    post(app_client, "/report", {"serial_number": "", "state_code": "MZ", "description": "Weights look filed down (sample)"})
    (rid,), = q("SELECT id FROM reports")
    login(app_client)                                   # Tamil Nadu
    assert post(app_client, f"/reports/{rid}/close", {"outcome": "Not mine to close"}).status_code == 403


def test_not_found_page_prefills_the_report_with_what_was_searched(app_client):
    body = app_client.get("/verify/SD-ZZZZ-ZZZZ").get_data(as_text=True)
    assert "/report?code=SD-ZZZZ-ZZZZ" in body


def test_dashboard_stays_short_with_hundreds_of_records(app_client):
    import seed_demo
    seed_demo.wipe()
    seed_demo.seed_full()
    login(app_client)
    page = app_client.get("/dashboard").get_data(as_text=True)
    assert page.count('<th scope="row"><a href="/verify/') <= 30 and "See all" in page
