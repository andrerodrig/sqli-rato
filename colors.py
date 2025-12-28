from rich.theme import Theme
from rich.console import Console


colors = {
    "clear": "\033[0m",
    "error": "\033[1;31m",
    "success": "\033[1;32m",
    "warning": "\033[1;33m",
    "info": "\033[1;34m"
}

custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "url": "underline blue"
})

console = Console(theme=custom_theme)
