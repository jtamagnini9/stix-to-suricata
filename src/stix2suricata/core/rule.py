"""Suricata rule representation and generation"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class SuricataRule:
    """Represents a Suricata/Snort rule"""
    action: str = "alert"
    protocol: str = "ip"
    src_ip: str = "any"
    src_port: str = "any"
    direction: str = "->"
    dst_ip: str = "any"
    dst_port: str = "any"
    options: List[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def add_option(self, option: str):
        """Add an option to the rule"""
        self.options.append(option)

    def to_rule(self, sid: int) -> str:
        """Convert to Suricata rule string"""
        opts = "; ".join(self.options)
        if opts:
            opts = f"({opts}; sid:{sid}; rev:1;)"
        else:
            opts = f"(sid:{sid}; rev:1;)"

        return f"{self.action} {self.protocol} {self.src_ip} {self.src_port} {self.direction} {self.dst_ip} {self.dst_port} {opts}"

    def to_rule_with_comment(self, sid: int, comment: str = None) -> str:
        """Convert to rule with optional comment"""
        rule = self.to_rule(sid)
        if comment:
            return f"# {comment}\n{rule}"
        return rule
