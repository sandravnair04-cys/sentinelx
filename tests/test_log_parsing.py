"""Windows, Linux and Wazuh parsing tests."""

from app.collectors.wazuh import parse_wazuh_alerts
from app.collectors.windows import parse_windows
from app.collectors.linux import parse_linux_auth


WIN_XML = """<Events>
<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID>
<TimeCreated SystemTime="2026-11-19T08:10:19.0000000Z"/><Computer>WIN-SRV-01</Computer></System>
<EventData><Data Name="TargetUserName">administrator</Data><Data Name="IpAddress">203.0.113.77</Data></EventData></Event>
</Events>"""

WIN_TEXT = (
    "2026-11-19T08:10:19Z EventID=4625 Account Name=administrator "
    "Source Network Address=203.0.113.77 Computer=WIN-SRV-01 failed logon\n"
)

LINUX_TEXT = (
    "Nov 19 08:41:03 ubuntu sshd[1205]: Failed password for invalid user admin from 198.51.100.23 port 40122 ssh2\n"
    "Nov 19 08:42:10 ubuntu sshd[1205]: Accepted password for root from 198.51.100.23 port 40136 ssh2\n"
    "Nov 19 08:42:11 ubuntu sudo: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash\n"
)


def test_windows_xml_parsing():
    events = parse_windows(WIN_XML)
    assert len(events) == 1
    assert events[0].event_code == "4625"
    assert events[0].action == "failure"
    assert events[0].username == "administrator"
    assert events[0].source_ip == "203.0.113.77"
    assert events[0].host == "WIN-SRV-01"


def test_windows_text_parsing():
    events = parse_windows(WIN_TEXT)
    assert len(events) == 1
    assert events[0].action == "failure"
    assert events[0].timestamp.year == 2026


def test_linux_auth_parsing():
    events = parse_linux_auth(LINUX_TEXT)
    assert len(events) == 3
    assert events[0].event_code == "AUTH_FAILED"
    assert events[0].username == "admin"
    assert events[1].action == "success"
    assert events[2].event_code == "SUDO"
    assert "command" in events[2].normalized


def test_linux_duplicate_detection():
    events = parse_linux_auth(LINUX_TEXT + LINUX_TEXT)
    assert len(events) == 3  # duplicates removed by event_uid


def test_wazuh_alert_parsing():
    payload = """[{"timestamp":"2026-11-19T09:10:02Z","agent":{"name":"WIN-01"},
    "rule":{"id":"5716","level":10,"description":"Multiple failed logins."},
    "data":{"srcip":"203.0.113.77","dstuser":"administrator"}}]"""
    events = parse_wazuh_alerts(payload)
    assert len(events) == 1
    assert events[0].source_type == "wazuh"
    assert events[0].username == "administrator"
