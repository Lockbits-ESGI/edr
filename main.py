#!/usr/bin/env python3
"""
MiniEDR — Lightweight Endpoint Detection & Response Tool

Main entry point. Supports two modes:
- scan: Single system snapshot without FIM
- monitor: Continuous FIM monitoring with periodic snapshots
"""

import argparse
import sys
import time
from pathlib import Path

try:
    from .config import load_config
    from .logger import setup_logging
    from .collector import get_system_snapshot, snapshot_to_dict
    from .fim import start_fim_monitor, get_alerts
    from .reporter import generate_json_report, generate_html_report
except ImportError:
    from config import load_config
    from logger import setup_logging
    from collector import get_system_snapshot, snapshot_to_dict
    from fim import start_fim_monitor, get_alerts
    from reporter import generate_json_report, generate_html_report


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="MiniEDR — Lightweight Endpoint Detection & Response Tool"
    )
    parser.add_argument(
        "--mode",
        choices=["scan", "monitor"],
        default="monitor",
        help="Operation mode (scan=single snapshot, monitor=continuous FIM)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config.yaml"),
        help="Path to configuration file",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./reports"),
        help="Output directory for reports",
    )

    args = parser.parse_args()

    # Create output directory
    args.output_dir.mkdir(parents=True, exist_ok=True)

    # Load configuration
    config = load_config(args.config)

    # Setup logging
    log_level = config.get("logging", {}).get("level", "INFO")
    logger = setup_logging(
        level=log_level,
        log_file=args.output_dir / "miniedr.log",
    )

    logger.info(f"MiniEDR starting in {args.mode} mode")

    try:
        if args.mode == "scan":
            # Single snapshot mode
            logger.info("Running in scan mode (single snapshot)")
            snapshot = get_system_snapshot()
            snapshot_dict = snapshot_to_dict(snapshot)
            generate_json_report(snapshot_dict, [], args.output_dir / "report.json")
            generate_html_report(snapshot_dict, [], args.output_dir / "report.html")
            logger.info(f"Reports generated in {args.output_dir}")
            return 0

        elif args.mode == "monitor":
            # Continuous monitoring mode
            logger.info("Running in monitor mode (continuous FIM)")
            watch_dirs = _get_watch_dirs(config)
            logger.info(f"Watching directories: {watch_dirs}")

            observer, alerts, lock = start_fim_monitor(watch_dirs)

            try:
                # Main loop
                while True:
                    time.sleep(5)
                    current_alerts = get_alerts(alerts, lock)
                    if current_alerts:
                        logger.info(f"Collected {len(current_alerts)} FIM alerts")

            except KeyboardInterrupt:
                logger.info("Received interrupt signal, stopping...")
                observer.stop()
                observer.join()

                # Generate final reports with all accumulated alerts
                final_alerts = get_alerts(alerts, lock)
                snapshot = get_system_snapshot()
                snapshot_dict = snapshot_to_dict(snapshot)
                generate_json_report(
                    snapshot_dict, final_alerts, args.output_dir / "report.json"
                )
                generate_html_report(
                    snapshot_dict, final_alerts, args.output_dir / "report.html"
                )
                logger.info(f"Final reports generated in {args.output_dir}")
                return 0

    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        return 1


def _get_watch_dirs(config: dict[str, object]) -> list[str]:
    """Get platform-specific watch directories from config."""
    import platform

    platform_system = platform.system()
    if platform_system == "Windows":
        return config.get("fim", {}).get("watch_dirs", {}).get("windows", [])
    else:
        return config.get("fim", {}).get("watch_dirs", {}).get("linux", [])


if __name__ == "__main__":
    sys.exit(main())
