"""CLI for warden — живой монитор рантайма агента."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from .banner import WARDEN_BANNER
from .monitor import watch

console = Console()


def _banner() -> None:
    console.print(f"[bold cyan]{WARDEN_BANNER}[/bold cyan]")


class BannerGroup(click.Group):
    def get_help(self, ctx: click.Context) -> str:
        _banner()
        return super().get_help(ctx)


@click.group(cls=BannerGroup)
def main() -> None:
    """MAD agent runtime monitor — ловит исполнение скрытых инструкций в потоке событий."""


def _ingest_to_db(report: dict) -> int | None:
    """Занести находки в общую БД finding-organizer. Недоступна → None (падаем в --json)."""
    try:
        fo_dir = Path(__file__).resolve().parent.parent.parent / "finding-organizer"
        if str(fo_dir) not in sys.path:
            sys.path.insert(0, str(fo_dir))
        from fo.store import ingest_tool_report  # type: ignore
        заведены = ingest_tool_report(report)
        return len(заведены)
    except Exception:
        return None


@main.command("watch")
@click.argument("events", type=click.Path())
@click.option("--json", "as_json", type=click.Path(), default=None,
              help="сохранить JSON-отчёт (контракт пайплайна / fallback для находок)")
def watch_cmd(events: str, as_json: str | None) -> None:
    """Тейлит поток событий агента (JSONL {id, input, output}), ловит исполнение канареек."""
    d = watch(events)

    if as_json:
        Path(as_json).write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")

    # 🔴 rc=2 «не состоялась» ≠ rc=0 «чисто»
    if d["verdict"] == "НЕ ПРОВЕРЕНО":
        console.print(f"[yellow]НЕ ПРОВЕРЕНО[/yellow]: {d['not_proven']}")
        raise SystemExit(2)

    if d["findings"]:
        # находки — в общую БД; недоступна → полагаемся на --json/stdout
        ingested = _ingest_to_db(d)
        t = Table(title=f"warden: {events}  ·  событий: {d['событий']}")
        t.add_column("событие"); t.add_column("вердикт")
        t.add_column("канарейка"); t.add_column("почему")
        for f in d["findings"]:
            t.add_row(str(f.get("id")), f"[red]{f['вердикт']}[/red]",
                      str(f.get("canary", "")), f["почему"])
        console.print(t)
        if ingested is not None:
            console.print(f"[dim]в общую БД (finding-organizer) заведено находок: {ingested}[/dim]")
        elif as_json:
            console.print(f"[dim]БД недоступна — находки сохранены в {as_json}[/dim]")
        else:
            console.print("[dim]БД недоступна и --json не задан — находки только в выводе выше[/dim]")

    цвет = "red" if d["verdict"] == "ПРОВАЛ" else "green"
    console.print(f"Вердикт: [{цвет}]{d['verdict']}[/{цвет}] — {d['почему']}")

    if d["verdict"] == "ПРОВАЛ":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
