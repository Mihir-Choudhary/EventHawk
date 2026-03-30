"""
Sentinel CLI — standalone command-line interface.

Usage:
  python -m sentinel.cli build  --evtx <folder> --output <dir> [--sigma <dir>]
  python -m sentinel.cli analyze --evtx <files...> --baseline <dir> [--report <file>]
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("sentinel.cli")


def _cmd_build(args: argparse.Namespace) -> int:
    from sentinel.analysis.parser import find_relevant_evtx_files
    from sentinel.baseline.builder import build_baseline
    import os

    evtx_dir = Path(args.evtx).resolve()
    output_dir = Path(args.output).resolve()
    sigma_dir = Path(args.sigma).resolve() if args.sigma else None

    # S2: Validate paths before use
    if not evtx_dir.exists():
        logger.error("EVTX folder does not exist: %s", evtx_dir)
        return 1
    if not evtx_dir.is_dir():
        logger.error("EVTX path is not a directory: %s", evtx_dir)
        return 1
    if sigma_dir and not sigma_dir.exists():
        logger.error("Sigma rules directory does not exist: %s", sigma_dir)
        return 1

    # S1: Warn if no explicit artifact key is configured
    if not os.environ.get("SENTINEL_ARTIFACT_KEY"):
        logger.warning(
            "SENTINEL_ARTIFACT_KEY env var not set. Artifact integrity uses a "
            "path-derived HMAC key — tamper detection only against accidental "
            "corruption, NOT adversarial forgery. Set SENTINEL_ARTIFACT_KEY for "
            "adversarial tamper protection."
        )

    def _cb(step: str, pct: float) -> None:
        bar = "#" * int(pct * 30)
        print(f"\r[{bar:<30}] {int(pct*100):3d}%  {step:<40}", end="", flush=True)

    logger.info("Scanning %s for relevant EVTX files ...", evtx_dir)
    evtx_paths = find_relevant_evtx_files(evtx_dir, progress_cb=_cb)
    print()
    if not evtx_paths:
        logger.error(
            "No EVTX files containing process-creation events (EID 4688/1) found in: %s\n"
            "Sentinel requires Security.evtx (EID 4688) or Sysmon.evtx (EID 1).",
            evtx_dir,
        )
        return 1

    logger.info("Found %d relevant EVTX file(s) — building baseline ...", len(evtx_paths))

    try:
        meta = build_baseline(evtx_paths, output_dir, sigma_dir, progress_cb=_cb)
        print()
        logger.info(
            "Baseline built: %d events, stability=%.2f, output=%s",
            meta.event_count, meta.stability_score, output_dir,
        )
        return 0
    except ValueError as exc:
        print()
        logger.error("Build failed: %s", exc)
        return 1


def _cmd_analyze(args: argparse.Namespace) -> int:
    from sentinel.analysis.engine import run_analysis
    from sentinel.baseline.persistence import artifacts_exist, load_artifacts
    from sentinel.report.generator import generate_report

    baseline_dir = Path(args.baseline).resolve()
    # S2: Validate baseline dir
    if not baseline_dir.exists() or not baseline_dir.is_dir():
        logger.error("Baseline directory does not exist: %s", baseline_dir)
        return 1
    if not artifacts_exist(baseline_dir):
        logger.error("Baseline artifacts not found in: %s", baseline_dir)
        return 1

    sigma_dir = Path(args.sigma).resolve() if args.sigma else None
    if sigma_dir and not sigma_dir.exists():
        logger.error("Sigma rules directory does not exist: %s", sigma_dir)
        return 1

    def _cb(step: str, pct: float) -> None:
        bar = "#" * int(pct * 30)
        print(f"\r[{bar:<30}] {int(pct*100):3d}%  {step:<40}", end="", flush=True)

    # Accept either a single folder or explicit file paths
    raw_evtx = [Path(f) for f in args.evtx]
    if len(raw_evtx) == 1 and raw_evtx[0].is_dir():
        from sentinel.analysis.parser import find_relevant_evtx_files
        logger.info("Scanning %s for relevant EVTX files ...", raw_evtx[0])
        target_paths = find_relevant_evtx_files(raw_evtx[0], progress_cb=_cb)
        print()
        if not target_paths:
            logger.error(
                "No EVTX files containing process-creation events found in: %s", raw_evtx[0]
            )
            return 1
        logger.info("Found %d relevant file(s)", len(target_paths))
    else:
        target_paths = raw_evtx
        missing = [p for p in target_paths if not p.exists()]
        if missing:
            for p in missing:
                logger.error("File not found: %s", p)
            return 1

    scored, metrics = run_analysis(target_paths, baseline_dir, sigma_dir, progress_cb=_cb)
    print()

    # Load meta for report
    meta, _, _, _ = load_artifacts(baseline_dir)

    report_path = Path(args.report) if args.report else None
    report = generate_report(scored, metrics, meta, report_path)

    t4 = metrics.get("tier4_critical", 0)
    t3 = metrics.get("tier3_highlight", 0)
    print(f"\n{'='*60}")
    print(f"  Events scored:    {metrics.get('events_scored', 0)}")
    print(f"  Suppressed (T1):  {metrics.get('tier1_suppressed', 0)} "
          f"({metrics.get('suppression_rate_pct', 0):.1f}%)")
    print(f"  Aggregate (T2):   {metrics.get('tier2_aggregate', 0)}")
    print(f"  Edge cases (T3):  {t3}")
    print(f"  Critical (T4):    {t4}")
    print(f"{'='*60}")

    if t4 > 0:
        print(f"\n*** {t4} CRITICAL ALERT(S) DETECTED ***")
        for section in report["critical_alerts"]:
            print(f"\n  [{section['technique']}]  {section['event_count']} event(s)")
            for ev in section["events"][:3]:
                print(f"    {ev['timestamp']}  {ev['process']} <- {ev['parent']}")
                print(f"    Score={ev['score']}  {ev['justification']}")

    if report_path:
        print(f"\nFull JSON report saved to: {report_path}")

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel Baseline Engine — deterministic EVTX differential analysis",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # build sub-command
    bp = sub.add_parser("build", help="Build a baseline from clean EVTX files")
    bp.add_argument("--evtx", required=True, help="Folder containing baseline .evtx files")
    bp.add_argument("--output", required=True, help="Output directory for artifacts")
    bp.add_argument("--sigma", default=None, help="Optional Sigma rules directory")

    # analyze sub-command
    ap = sub.add_parser("analyze", help="Analyze target EVTX files against a baseline")
    ap.add_argument("--evtx", required=True, nargs="+", help="Target .evtx files")
    ap.add_argument("--baseline", required=True, help="Baseline artifacts directory")
    ap.add_argument("--sigma", default=None, help="Optional Sigma rules directory")
    ap.add_argument("--report", default=None, help="Output JSON report file path")

    args = parser.parse_args()

    if args.command == "build":
        return _cmd_build(args)
    elif args.command == "analyze":
        return _cmd_analyze(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
