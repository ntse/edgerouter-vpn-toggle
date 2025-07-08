from flask import Flask, jsonify, render_template
import os
import requests
import ssl

app = Flask(__name__)

ROUTER_HOST = os.environ.get("ROUTER_HOST")
ROUTER_USERNAME = os.environ.get("ROUTER_USERNAME")
ROUTER_PASSWORD = os.environ.get("ROUTER_PASSWORD")

# SSL Patch taken from https://stackoverflow.com/a/55320969
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    # Legacy Python that doesn't verify HTTPS certificates by default
    pass
else:
    # Handle target environment that doesn't support HTTPS verification
    ssl._create_default_https_context = _create_unverified_https_context


def login_and_get_session():
    session = requests.Session()
    form_data = {"username": ROUTER_USERNAME, "password": ROUTER_PASSWORD}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    _ = session.post(
        f"https://{ROUTER_HOST}/",
        data=form_data,
        headers=headers,
        verify=False,
        allow_redirects=False,
    )

    cookies = session.cookies.get_dict()
    csrf_token = cookies.get("X-CSRF-TOKEN")
    if not csrf_token or "PHPSESSID" not in cookies:
        raise RuntimeError("Missing CSRF token or PHPSESSID in cookies. Login failed.")

    return session, csrf_token


def get_vpn_rule_state(session, csrf_token):
    params = [
        ("node[]", "firewall"),
        ("node[]", "modify"),
        ("node[]", "SOURCE_ROUTE"),
        ("node[]", "rule"),
        ("node[]", "20"),
    ]
    headers = {"X-CSRF-TOKEN": csrf_token}
    response = session.get(
        f"https://{ROUTER_HOST}/api/edge/getcfg.json",
        params=params,
        headers=headers,
        verify=False,
    )
    children = response.json().get("GETCFG", {}).get("children", {})
    return "disable" not in children  # True if VPN is active


def set_vpn_state(session, csrf_token, enable: bool):
    headers = {"X-CSRF-TOKEN": csrf_token}
    action = "DELETE" if enable else "SET"
    payload = {
        action: {
            "firewall": {
                "modify": {"SOURCE_ROUTE": {"rule": {"20": {"disable": None}}}}
            }
        }
    }

    response = session.post(
        f"https://{ROUTER_HOST}/api/edge/batch.json",
        headers=headers,
        json=payload,
        verify=False,
    )
    if response.status_code != 200:
        raise RuntimeError(
            f"{action} request failed: {response.status_code} {response.text}"
        )

    return get_vpn_rule_state(session, csrf_token)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/vpn-status", methods=["GET"])
def vpn_status():
    session, csrf_token = login_and_get_session()
    vpn_on = get_vpn_rule_state(session, csrf_token)
    return jsonify({"vpnOn": vpn_on})


@app.route("/toggle-vpn", methods=["POST"])
def toggle_vpn_route():
    session, csrf_token = login_and_get_session()
    current = get_vpn_rule_state(session, csrf_token)
    updated = set_vpn_state(session, csrf_token, enable=not current)
    return jsonify({"vpnOn": updated})


if __name__ == "__main__":
    app.run(debug=True)
