import argparse

from colors import console


def setup_cli() -> None:
    parser = argparse.ArgumentParser(
        description="SQLi Ratao",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument("--injected-uri", required=True, help="Target endpoint URI with injected SQL.")
    parser.add_argument("--cookie", help="Session cookie. Optional")
    parser.add_argument("--db", choices=['mysql'], help="SGBD. Optional")

    args = parser.parse_args()

    console.print("\n[bold cyan]SQLi RATAO v1.0[/bold cyan]")
    console.print("="*40)
