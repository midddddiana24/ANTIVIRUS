"""Firewall rule engine — evaluates and enforces per-application/IP/port rules.

Two modes, deliberately separated:

* **Evaluate** (always on): every observed connection is checked against the rule table
  and the blocklist, and the verdict is logged to the timeline. This is the "detect"
  half that works for any user, elevated or not.
* **Enforce** (opt-in, ``firewall.enforce_rules``): the engine also programs the OS
  firewall — ``netsh advfirewall`` on Windows, ``iptables`` on POSIX — to block or
  allow traffic. Only ``ShieldEX-`` prefixed rule names are ever created or removed, so
  co-existing rules from other products are never touched. Enforcement is dry-run by
  default: a mis-configured template that blocks all traffic must never be able to
  brick the machine without an explicit user opt-in.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.config import Config
from core.database import Database
from core.firewall.ip_blocklist import IPBlocklist
from core.timeline import EventType, Severity, TimelineLogger

logger = logging.getLogger(__name__)

__all__ = ["RuleEngine", "Verdict", "OS_RULE_PREFIX"]

OS_RULE_PREFIX = "ShieldEX-"

#: Creation flags so a netsh/iptables child never flashes a console window on Windows.
CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0


@dataclass
class Verdict:
    """The outcome of evaluating one connection against the rule table."""

    action: str  # "allow" | "block" | "monitor"
    reason: str
    rule_id: int | None = None
    rule_name: str | None = None

    @property
    def blocked(self) -> bool:
        return self.action == "block"


class RuleEngine:
    """Rule evaluation for observed connections, plus opt-in OS enforcement."""

    def __init__(
        self,
        config: Config,
        db: Database,
        timeline: TimelineLogger,
        blocklist: IPBlocklist,
    ) -> None:
        self.cfg = config
        self.db = db
        self.timeline = timeline
        self.blocklist = blocklist
        self._elevated = None
        self._elevation_lock = threading.Lock()

    # ================================================================== evaluation
    def evaluate(
        self,
        remote_ip: str,
        process_name: str = "",
        remote_port: int | None = None,
        protocol: str = "TCP",
        direction: str = "outbound",
    ) -> Verdict:
        """Decide what happens to one connection. Order matters:

        1. trusted IP/network → allow (the user vouched for it);
        2. blocklist match → block (highest priority after trust);
        3. first matching stored rule (block rules win over allow rules on ties);
        4. default ``monitor`` — no opinion, keep watching.
        """
        if self.blocklist.is_trusted(remote_ip):
            return Verdict("allow", "trusted IP")
        if self.blocklist.is_blocked(remote_ip):
            return Verdict("block", "blocklisted IP")

        rules = self.db.get_firewall_rules(enabled=True)
        matches: list[dict[str, Any]] = []
        for rule in rules:
            if self._rule_matches(rule, remote_ip, process_name, remote_port, protocol, direction):
                matches.append(rule)

        if matches:
            blocks = [rule for rule in matches if str(rule.get("action", "")).lower() == "block"]
            chosen = blocks[0] if blocks else matches[0]
            action = str(chosen.get("action", "monitor")).lower()
            return Verdict(
                action if action in ("allow", "block", "monitor") else "monitor",
                f'rule "{chosen.get("name", "?")}"',
                rule_id=int(chosen.get("id", 0)) or None,
                rule_name=str(chosen.get("name", "")),
            )
        return Verdict("monitor", "no matching rule (default)")

    @staticmethod
    def _rule_matches(
        rule: dict[str, Any],
        remote_ip: str,
        process_name: str,
        remote_port: int | None,
        protocol: str,
        direction: str,
    ) -> bool:
        """Check one rule's every non-empty constraint against the connection."""
        import ipaddress

        rule_ip = str(rule.get("remote_ip", "") or "").strip()
        if rule_ip:
            try:
                if "/" in rule_ip:
                    if ipaddress.ip_address(remote_ip) not in ipaddress.ip_network(rule_ip, strict=False):
                        return False
                elif ipaddress.ip_address(remote_ip) != ipaddress.ip_address(rule_ip):
                    return False
            except ValueError:
                return False

        rule_port = rule.get("remote_port")
        if rule_port not in (None, "", 0):
            try:
                if remote_port is None or int(remote_port) != int(rule_port):
                    return False
            except (TypeError, ValueError):
                return False

        rule_protocol = str(rule.get("protocol", "") or "").strip().lower()
        if rule_protocol and rule_protocol != protocol.lower():
            return False

        rule_direction = str(rule.get("direction", "") or "").strip().lower()
        if rule_direction and rule_direction not in ("any", direction.lower()):
            return False

        rule_process = str(rule.get("app_path", "") or "").strip().lower()
        if rule_process:
            if rule_process not in (process_name.lower(), Path(process_name).name.lower()):
                return False

        return True

    # ================================================================== profiles
    def set_profile_enabled(self, profile: str, enabled: bool) -> bool:
        """Toggle one of the domain/private/public profiles and re-apply its rules."""
        normalized = profile.strip().lower()
        if normalized not in ("domain", "private", "public"):
            logger.warning("Unknown firewall profile %r", profile)
            return False
        self.cfg.set(f"firewall.profiles.{normalized}", bool(enabled))
        # The app shell and the dashboard read firewall_enabled_* (seeded by main from
        # config.json), so that is the key written here; the redundant
        # firewall_enabled_* / firewall_profile_ pair previously diverged because this
        # line wrote the *other* spelling and the toggle then "reset" on every restart.
        self.db.set_bool_setting(f"firewall_enabled_{normalized}", bool(enabled))

        self.timeline.log_firewall(
            EventType.PROFILE_CHANGED,
            f"Profile '{normalized}' {'enabled' if enabled else 'disabled'}",
            Severity.INFO,
        )
        self.apply_all()
        return True

    def active_profiles(self) -> list[str]:
        """The currently enabled profile names."""
        return [
            profile
            for profile in ("domain", "private", "public")
            if self.db.get_bool_setting(f"firewall_enabled_{profile}", True)
        ]

    # ================================================================== enforcement
    @property
    def elevated(self) -> bool:
        """Whether the process runs with admin/root rights (cached)."""
        if self._elevated is not None:
            return self._elevated
        with self._elevation_lock:
            if self._elevated is None:
                if sys.platform == "win32":
                    try:
                        import ctypes

                        self._elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())
                    except Exception:
                        self._elevated = False
                else:
                    self._elevated = sys.platform != "win32" and os.geteuid() == 0
            return self._elevated

    def enforce_enabled(self) -> bool:
        """True when both the config opt-in and elevation requirements are met."""
        return bool(self.cfg.get("firewall.enforce_rules", False))

    def apply_all(self) -> bool:
        """(Re)apply all enabled rules to the OS firewall when enforcement is on."""
        if not self.enforce_enabled():
            self.timeline.log_firewall(
                EventType.RULE_DRY_RUN,
                "Rules are in dry-run mode (enforce_rules is false); nothing was programmed",
                Severity.INFO,
            )
            return False
        if not self.elevated:
            self.timeline.log_firewall(
                EventType.ENGINE_ERROR,
                "Cannot program OS firewall rules without elevation",
                Severity.MEDIUM,
            )
            return False

        rules = self.db.get_firewall_rules(enabled=True)
        applied = 0
        for rule in rules:
            if self._program_rule(rule):
                applied += 1
        self.timeline.log_firewall(
            EventType.RULE_APPLIED,
            f"Applied {applied}/{len(rules)} rule(s) to the OS firewall",
            Severity.INFO,
        )
        return True

    def block_ip(self, ip: str, label: str = "") -> bool:
        """Block an address at the OS level with a named in+out rule pair."""
        if not self.enforce_enabled():
            logger.info("block_ip: enforcement disabled; only recording in the blocklist")
            return False
        if not self.elevated:
            logger.warning("block_ip: not elevated; only recording in the blocklist")
            return False

        created = False
        for direction in ("in", "out"):
            name = f"{OS_RULE_PREFIX}Block IP {ip} ({direction})"
            created = self._netsh_block(ip, direction, name) or created
        if created:
            self.timeline.log_firewall(
                EventType.IP_BLOCKED,
                f"OS firewall now blocks {ip} (in+out)",
                Severity.MEDIUM,
                ip,
            )
        return created

    # ------------------------------------------------------------------ OS plumbing
    def _run_command(self, args: list[str]) -> tuple[int, str]:
        """Run a subprocess without a console window; returns (returncode, output)."""
        try:
            completed = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=20,
                creationflags=CREATE_NO_WINDOW,
            )
            output = (completed.stdout or "") + (completed.stderr or "")
            return completed.returncode, output
        except (OSError, subprocess.TimeoutExpired) as exc:
            logger.error("Command %s failed: %s", args[0], exc)
            return 1, str(exc)

    def _netsh_block(self, ip: str, direction: str, rule_name: str) -> bool:
        """Create one netsh block rule (Windows)."""
        args = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            f"dir={direction}",
            "action=block",
            f"remoteip={ip}",
            "enable=yes",
        ]
        code, output = self._run_command(args)
        if code != 0:
            logger.error("netsh add rule failed (%s): %s", code, output.strip())
            return False
        return True

    def _program_rule(self, rule: dict[str, Any]) -> bool:
        """Translate one stored rule into an OS firewall command."""
        action = str(rule.get("action", "")).lower()
        if action not in ("allow", "block"):
            return False  # monitor rules exist only in the app

        if sys.platform == "win32":
            return self._program_rule_netsh(rule)
        return self._program_rule_iptables(rule)

    def _program_rule_netsh(self, rule: dict[str, Any]) -> bool:
        """Build and run the netsh command for one rule."""
        name = f"{OS_RULE_PREFIX}{str(rule.get('name', rule.get('id', 'rule')))}"
        direction = str(rule.get("direction", "outbound")).lower()
        netsh_direction = "out" if direction.startswith("out") else "in"
        netsh_action = "allow" if str(rule.get("action")).lower() == "allow" else "block"

        args = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={name}",
            f"dir={netsh_direction}",
            f"action={netsh_action}",
        ]
        remote_ip = str(rule.get("remote_ip", "") or "").strip()
        if remote_ip:
            args.append(f"remoteip={remote_ip}")
        remote_port = rule.get("remote_port")
        if remote_port not in (None, "", 0):
            protocol = str(rule.get("protocol", "TCP")).upper()
            args.append(f"protocol={protocol}")
            args.append(f"remoteport={remote_port}")
        app_path = str(rule.get("app_path", "") or "").strip()
        if app_path:
            args.append(f"program={app_path}")
        args.append("enable=yes")

        code, output = self._run_command(args)
        if code != 0:
            logger.error("Programming rule %s failed: %s", name, output.strip())
            return False
        return True

    def _program_rule_iptables(self, rule: dict[str, Any]) -> bool:
        """Build and run the iptables command for one rule (POSIX fallback)."""
        action = str(rule.get("action")).lower()
        direction = str(rule.get("direction", "outbound")).lower()
        protocol = str(rule.get("protocol", "TCP")).upper()
        remote_ip = str(rule.get("remote_ip", "") or "").strip()
        remote_port = rule.get("remote_port")

        chain = "OUTPUT" if direction.startswith("out") else "INPUT"
        target = "ACCEPT" if action == "allow" else "DROP"
        args = ["iptables", "-A", chain, "-j", target]
        if protocol:
            args[3:3] = ["-p", protocol]
        if remote_ip:
            args[3:3] = ["-d", remote_ip]
        if remote_port not in (None, "", 0):
            args[3:3] = ["--dport", str(remote_port)]

        code, output = self._run_command(args)
        if code != 0:
            logger.error("Programming iptables rule failed: %s", output.strip())
            return False
        return True

    # ================================================================== templates
    def create_rule_from_template(self, template_name: str) -> int | None:
        """Instantiate a known template rule. Returns the new rule id or None."""
        templates = {
            "block_rdp_in": {
                "name": "Block inbound RDP",
                "action": "block",
                "remote_port": "3389",
                "protocol": "TCP",
                "direction": "inbound",
                "description": "Template: block inbound Remote Desktop",
            },
            "block_smb_out": {
                "name": "Block outbound SMB",
                "action": "block",
                "remote_port": "445",
                "protocol": "TCP",
                "direction": "outbound",
                "description": "Template: block outbound SMB file sharing",
            },
            "allow_updates": {
                "name": "Allow OS update traffic",
                "action": "allow",
                "remote_port": "443",
                "protocol": "TCP",
                "direction": "outbound",
                "app_path": "wuauclt.exe",
                "description": "Template: permit Windows Update traffic",
            },
            "block_telnet_out": {
                "name": "Block outbound Telnet",
                "action": "block",
                "remote_port": "23",
                "protocol": "TCP",
                "direction": "outbound",
                "description": "Template: block unencrypted Telnet",
            },
        }
        template = templates.get(template_name)
        if template is None:
            return None
        fields = dict(template)
        name = str(fields.pop("name"))
        rule_id = self.db.add_firewall_rule(name=name, **fields)
        if rule_id and rule_id > 0:
            self.timeline.log_firewall(
                EventType.RULE_CREATED,
                f'Rule created from template "{template_name}": "{name}"',
                Severity.INFO,
            )
            return rule_id
        return None

    # ================================================================== lifecycle
    def stop(self) -> None:
        """No background thread of its own; present for engine-registry symmetry."""
