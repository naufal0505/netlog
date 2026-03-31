import time
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align

console = Console()


ASCII_BANNER = r"""
███╗   ██╗███████╗████████╗██╗      ██████╗  ██████╗     
████╗  ██║██╔════╝╚══██╔══╝██║     ██╔═══██╗██╔════╝     
██╔██╗ ██║█████╗     ██║   ██║     ██║   ██║██║  ███╗    
██║╚██╗██║██╔══╝     ██║   ██║     ██║   ██║██║   ██║    
██║ ╚████║███████╗   ██║   ███████╗╚██████╔╝╚██████╔╝    
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝  ╚═════╝     
"""


def show_banner(version: str = "v1.1.2", repo_label: str = "github.com/USERNAME/netlog-ai"):
    banner_text = Text()
    banner_text.append(ASCII_BANNER, style="bold cyan")
    banner_text.append(f"\n{' ' * 56}{version}\n", style="bold white")
    banner_text.append(f"{' ' * 24}{repo_label}", style="green")

    panel = Panel(
        Align.center(banner_text),
        border_style="bright_blue",
        padding=(1, 2),
        title="[bold white]NetLog Analyzer[/bold white]",
        subtitle="[bold green]Network Threat Hunting Toolkit[/bold green]",
    )

    console.print(panel)


def show_startup_animation():
    steps = [
        "[cyan]Initializing modules...[/cyan]",
        "[cyan]Loading analyzers...[/cyan]",
        "[cyan]Preparing threat engine...[/cyan]",
        "[cyan]Ready.[/cyan]",
    ]

    for step in steps:
        console.print(step)
        time.sleep(0.25)