from rich.console import Console
from rich.theme import Theme

custom_theme = Theme({
    "info": "blue",
    "success": "green",
    "warning": "yellow",
    "error": "red",
    "finding": "magenta bold",
    "header": "cyan bold"
})

console = Console(theme=custom_theme)

class Icons:
    INFO = "[blue][*][/blue]"
    SUCCESS = "[green][+][/green]"
    WARNING = "[yellow][!][/yellow]"
    ERROR = "[red][-][/red]"
    FINDING = "[magenta bold][★][/magenta bold]"

def print_banner():
    banner = """[cyan]
██╗    ██╗██╗███╗   ██╗███████╗███╗   ██╗██╗   ██╗███╗   ███╗
██║    ██║██║████╗  ██║██╔════╝████╗  ██║██║   ██║████╗ ████║
██║ █╗ ██║██║██╔██╗ ██║█████╗  ██╔██╗ ██║██║   ██║██╔████╔██║
██║███╗██║██║██║╚██╗██║██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║
╚███╔███╔╝██║██║ ╚████║███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
 ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝[/cyan]
[yellow]        Windows HackTheBox Auto-Enumeration Tool[/yellow]
[white]                    by VegeLasagne[/white]
"""
    console.print(banner, highlight=False)

def print_status(message: str, status: str = "info"):
    """Print formatted status message"""
    icons = {
        'info': Icons.INFO,
        'success': Icons.SUCCESS,
        'warning': Icons.WARNING,
        'error': Icons.ERROR,
        'finding': Icons.FINDING,
    }
    icon = icons.get(status, icons['info'])
    console.print(f"{icon} {message}")

def print_header(title: str):
    """Print section header"""
    console.print(f"\n[header]{'='*60}\n {title}\n{'='*60}[/header]")
