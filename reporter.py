"""Report generation in JSON and HTML formats."""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger("miniedr")


class DateTimeEncoder(json.JSONEncoder):
    """JSON encoder that handles datetime objects."""

    def default(self, o: object) -> object:
        if isinstance(o, datetime):
            return o.isoformat()
        return super().default(o)


def generate_json_report(
    snapshot: dict[str, object],
    fim_alerts: list[dict[str, object]],
    output_path: Path,
) -> bool:
    """Generate JSON report with system snapshot and FIM alerts.

    Args:
        snapshot: System snapshot dict from collector.
        fim_alerts: List of FIM alert dicts.
        output_path: Path to write JSON report.

    Returns:
        True if successful, False otherwise.
    """
    report = {
        "timestamp": datetime.now().isoformat(),
        "system_snapshot": snapshot,
        "fim_alerts": fim_alerts,
        "alert_count": len(fim_alerts),
    }

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, cls=DateTimeEncoder)
        logger.info(f"JSON report written to {output_path}")
        return True
    except Exception as e:
        logger.error(f"Error writing JSON report: {e}")
        return False


def generate_html_report(
    snapshot: dict[str, object],
    fim_alerts: list[dict[str, object]],
    output_path: Path,
    template_dir: Optional[Path] = None,
) -> bool:
    """Generate HTML report with system snapshot and FIM alerts.

    Args:
        snapshot: System snapshot dict from collector.
        fim_alerts: List of FIM alert dicts.
        output_path: Path to write HTML report.
        template_dir: Directory containing Jinja2 templates (default: ./templates).

    Returns:
        True if successful, False otherwise.
    """
    if template_dir is None:
        template_dir = Path("templates")

    output_path = Path(output_path)
    if not template_dir.exists():
        logger.error(f"Template directory not found: {template_dir}")
        return False

    try:
        env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        template = env.get_template("report.html.j2")

        malicious_count = sum(1 for a in fim_alerts if a.get("event_type") == "created")
        suspicious_count = sum(
            1 for a in fim_alerts if a.get("event_type") == "modified"
        )

        html_content = template.render(
            timestamp=datetime.now().isoformat(),
            snapshot=snapshot,
            fim_alerts=fim_alerts,
            alert_count=len(fim_alerts),
            malicious_count=malicious_count,
            suspicious_count=suspicious_count,
        )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        logger.info(f"HTML report written to {output_path}")
        return True

    except Exception as e:
        logger.error(f"Error generating HTML report: {e}")
        return False
