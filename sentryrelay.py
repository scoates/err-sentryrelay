import hmac
import hashlib
import json
import re

from errbot import BotPlugin, webhook, ValidationException
from flask import abort
import requests


class SentryRelay(BotPlugin):
    """
    Relays information from Sentry to IRC
    """

    API_PREFIX = "https://sentry.io/api/0"
    ISSUE_PATH = "{prefix}/issues/{issue_id}/"

    def get_configuration_template(self):
        return {
            "CLIENT_SECRET": "f9876",
            "TOKENS": {
                r"project_slug_regex-.*": "a1234",
                r".*?-project_slug_regex2": "b5678",
            },
            "IGNORE": ["annoying_project_slug_regex-.*"],
        }

    def check_configuration(self, configuration):
        for k in ["TOKENS", "CLIENT_SECRET"]:
            # make this friendlier
            if k not in configuration:
                raise ValidationException(f"configuration must contain {k}")
        if "IGNORE" in configuration and not isinstance(configuration["IGNORE"], list):
            raise ValidationException("IGNORE must be a list of regular expressions")

    def activate(self):
        if not self.config:
            self.log.info("Not configured. Forbidding activation.")
            return
        if "IGNORE" not in self.config:
            self.config["IGNORE"] = []
        super().activate()

    def _has_valid_sig(self, request):
        data = request.stream.read()
        sig = request.headers.get("Sentry-Hook-Signature")

        if sig is None:
            self.log.debug("No signature")
            return False

        digest = hmac.new(
            key=self.config["CLIENT_SECRET"].encode("utf-8"),
            msg=data,
            digestmod=hashlib.sha256,
        ).hexdigest()

        if digest != sig:
            self.log.debug("Invalid signature.")
            return False

        self.log.debug("Valid signature.")
        return data

    def _is_ignored(self, project_slug):
        for pat in self.config["IGNORE"]:
            if re.match(pat, project_slug):
                return True
        return False

    def _get_project_token(self, project_slug):
        for pat, token in self.config["TOKENS"].items():
            if re.match(pat, project_slug):
                return token
        return None

    def _get_issue(self, issue_id, token):
        url = self.ISSUE_PATH.format(prefix=self.API_PREFIX, issue_id=issue_id)
        headers = {"Authorization": f"Bearer {token}"}
        req = requests.get(url, headers=headers)
        if req.status_code != 200:
            return False
        return req.json()

    @webhook("/sentry/<channel>", raw=True)
    def sentry_notification(self, request, channel):

        req_data = self._has_valid_sig(request)
        if not req_data:
            self.log.warn("Invalid signature.")
            abort(403)

        # need to do it this way because of the raw request + hash
        payload = json.loads(req_data)

        channel = f"#{channel}"
        found_channel = False
        for room in self.rooms():
            if room.room == channel:
                found_channel = True
                break
        if not found_channel:
            self.log.warn("Can't relay to non-present channels.")
            abort(404)

        self.log.info(f"Relaying to {channel}")
        target = self.build_identifier(channel)

        try:
            project_slug = payload["data"]["issue"]["project"]["slug"]
        except KeyError:
            self.log.warn("Invalid message; no project slug")
            project_slug = "(no project slug)"

        if self._is_ignored(project_slug):
            return "Valid message, not relayed.", 200

        # project not ignored
        token = self._get_project_token(project_slug)
        if token is None:
            abort(403, "Valid message, but no token found.")

        issue = self._get_issue(payload["data"]["issue"]["id"], token)
        issue_url = issue["permalink"]

        action = payload["action"]
        title = payload["data"]["issue"]["title"]

        message = (
            f"{self._color_string('red', 'SENTRY')} [{self._format_project(project_slug)}]"
            + f" issue {self._format_action(action)}:"
            + f" {title} {self._format_url(issue_url)}"
        )

        self.send(target, message)
        return f"Message relayed to {target}", 202

    @staticmethod
    def _color_string(color, string):
        return "`" + string + "`{:color='" + color + "'}"

    def _format_project(self, url):
        return self._color_string("cyan", url)

    def _format_action(self, branch):
        return self._color_string("magenta", branch)

    def _format_url(self, url):
        return self._color_string("cyan", url)
