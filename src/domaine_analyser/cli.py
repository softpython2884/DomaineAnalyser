"""Interface en ligne de commande.

Deux niveaux de sortie, parce que deux usages coexistent : une synthèse dense
au terminal pour l'analyse interactive, et le rapport Markdown complet écrit
dans un fichier pour l'archivage ou la transmission. `--fail-on` rend enfin la
commande utilisable en intégration continue, où seul le code de sortie compte.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__

# Sous-système des tests actifs (émission réelle de messages).
from .active import mx_probe
from .active import report as active_report
from .active import scenarios as spoof_scenarios
from .active.runner import run_spoof_campaign
from .active.safety import SafetyError
from .active.settings import load_mail_test_config
from .config import load_settings
from .models import DomainReport, Severity
from .net.resolver import DnsResolver
from .pipeline import analyze_domain
from .report import json_out
from .report import markdown as markdown_report
from .score import severity_counts

app = typer.Typer(
    name="domaine-analyser",
    help="Audit de sécurité email et forensic d'usurpation.",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()
err_console = Console(stderr=True)

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"domaine-analyser {__version__}")
        raise typer.Exit


@app.callback()
def main_callback(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Affiche la version."
    ),
) -> None:
    """Point d'entrée commun."""


@app.command("domain")
def domain_command(
    domain: str = typer.Argument(..., help="Domaine à auditer, par exemple example.com"),
    deep: bool = typer.Option(
        False, "--deep", help="Sonde un dictionnaire de sélecteurs DKIM plus large."
    ),
    selector: list[str] = typer.Option(
        [], "--selector", "-s", help="Sélecteur DKIM connu à tester en priorité (répétable)."
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Écrit le rapport Markdown complet dans ce fichier."
    ),
    json_output: Path | None = typer.Option(
        None, "--json", help="Écrit le rapport JSON dans ce fichier."
    ),
    show_markdown: bool = typer.Option(
        False, "--markdown", help="Affiche le rapport Markdown complet au lieu de la synthèse."
    ),
    no_registration: bool = typer.Option(
        False, "--no-registration", help="N'interroge ni RDAP ni WHOIS (plus rapide)."
    ),
    resolver: list[str] = typer.Option(
        [], "--resolver", help="Résolveur DNS à utiliser (répétable). Par défaut 1.1.1.1 et 8.8.8.8."
    ),
    fail_on: str | None = typer.Option(
        None,
        "--fail-on",
        help="Code de sortie non nul si un constat atteint cette gravité "
        "(critical, high, medium, low). Utile en intégration continue.",
    ),
) -> None:
    """Audite un domaine : DNS, SPF, DKIM, DMARC, CAA, services tiers."""
    settings = load_settings()
    if resolver:
        settings = settings.with_overrides(resolvers=tuple(resolver))

    threshold = _parse_severity(fail_on) if fail_on else None

    try:
        with console.status(f"Analyse de {domain}…", spinner="dots"):
            report = analyze_domain(
                domain,
                settings,
                deep=deep,
                extra_selectors=tuple(selector),
                skip_registration=no_registration,
            )
    except KeyboardInterrupt:
        err_console.print("[yellow]Analyse interrompue.[/yellow]")
        raise typer.Exit(code=130) from None

    if output:
        _write(output, markdown_report.render(report))
        console.print(f"[green]Rapport Markdown écrit :[/green] {output}")
    if json_output:
        _write(json_output, json_out.render(report))
        console.print(f"[green]Rapport JSON écrit :[/green] {json_output}")

    if show_markdown:
        # Sortie brute, sans mise en forme rich : elle est destinée à être
        # redirigée vers un fichier ou un autre programme.
        print(markdown_report.render(report))
    else:
        _print_summary(report)

    if threshold is not None and any(
        finding.severity.rank <= threshold.rank for finding in report.findings
    ):
        raise typer.Exit(code=2)


@app.command("doctor")
def doctor_command() -> None:
    """Diagnostique l'environnement et signale ce qui limiterait un audit."""
    settings = load_settings()

    table = Table(title="Diagnostic de l'environnement", title_justify="left")
    table.add_column("Élément")
    table.add_column("État")
    table.add_column("Conséquence si absent")

    ok = Text("OK", style="green")
    degraded = Text("dégradé", style="yellow")
    missing = Text("absent", style="red")

    version = sys.version_info
    table.add_row(
        "Python",
        ok if version >= (3, 10) else missing,
        f"{version.major}.{version.minor}.{version.micro} — minimum requis : 3.10",
    )

    for module, label, consequence in (
        ("dns", "dnspython", "aucune résolution DNS possible"),
        ("spf", "pyspf", "pas de rejeu SPF sur une adresse"),
        ("dkim", "dkimpy", "pas de vérification de signature DKIM"),
        ("cryptography", "cryptography", "taille des clés DKIM non analysée"),
        ("httpx", "httpx", "RDAP indisponible"),
        ("tldextract", "tldextract", "domaine organisationnel mal déterminé"),
    ):
        try:
            __import__(module)
            table.add_row(label, ok, "—")
        except ImportError:
            table.add_row(label, missing, consequence)

    # Seul `whois` est consulté, et seulement en dernier recours : le client
    # WHOIS natif de l'outil couvre déjà le besoin. Son absence n'a donc pas
    # d'incidence sur la validité d'un audit.
    whois_path = shutil.which("whois")
    table.add_row(
        "binaire `whois`",
        ok if whois_path else degraded,
        whois_path
        or "absent — le client WHOIS natif prend le relais, sortie brute un peu moins riche",
    )

    # -- vérifications réseau
    dns_state, dns_detail = _check_dns(settings)
    table.add_row("Résolution DNS", dns_state, dns_detail)

    rdap_state, rdap_detail = _check_http(settings, "https://rdap.org/domain/example.com")
    table.add_row("Accès RDAP", rdap_state, rdap_detail)

    table.add_row(
        "Clé Gemini",
        ok if settings.ai_available else degraded,
        "présente — option --ai disponible"
        if settings.ai_available
        else "absente — enrichissement --ai indisponible (sans effet sur l'audit)",
    )

    table.add_row("Base DMARC", Text("—", style="dim"), str(settings.db_path))
    table.add_row("Cache", Text("—", style="dim"), str(settings.cache_dir))

    console.print(table)


# ---------------------------------------------------------------------------
# Rendu de la synthèse
# ---------------------------------------------------------------------------


def _print_summary(report: DomainReport) -> None:
    score = report.score
    style = "green" if score.total >= 75 else "yellow" if score.total >= 40 else "red"

    header = Text()
    header.append(f"{report.domain}\n", style="bold")
    header.append(f"{score.total}/100  ", style=f"bold {style}")
    header.append(f"(note {score.grade})", style=style)

    if report.verdict.spoofable:
        header.append("\n\nUSURPABLE", style="bold red")
        header.append(
            "\nUn tiers peut envoyer un message affichant ce domaine en expéditeur\n"
            "et atteindre la boîte de réception."
        )
    else:
        header.append("\n\nPROTÉGÉ", style="bold green")
        header.append("\nUne politique DMARC en application couvre le domaine.")

    if report.verdict.subdomains_spoofable:
        header.append("\n\nLes sous-domaines restent usurpables.", style="yellow")

    console.print(Panel(header, border_style=style, padding=(1, 2)))

    for reason in report.verdict.reasons:
        console.print(f"  · {reason}")

    if not report.findings:
        console.print("\n[green]Aucun risque relevé.[/green]")
        return

    counts = severity_counts(report.findings)
    summary = "  ".join(
        f"[{_SEVERITY_STYLE[severity]}]{counts[severity]} {severity.label_fr.lower()}"
        f"[/{_SEVERITY_STYLE[severity]}]"
        for severity in _SEVERITY_ORDER
        if counts[severity]
    )
    console.print(f"\n{len(report.findings)} constats : {summary}\n")

    table = Table(show_lines=False, box=None, pad_edge=False)
    table.add_column("Code", style="dim", no_wrap=True)
    table.add_column("Gravité", no_wrap=True)
    table.add_column("Constat")

    for finding in report.findings:
        table.add_row(
            finding.code,
            Text(finding.severity.label_fr, style=_SEVERITY_STYLE[finding.severity]),
            finding.title,
        )
    console.print(table)

    if report.warnings:
        console.print("\n[yellow]Limites de cet audit :[/yellow]")
        for warning in report.warnings:
            console.print(f"  · {warning}")

    console.print(
        "\n[dim]Rapport détaillé — impact et correction de chaque constat :"
        f"\n  da domain {report.domain} --output rapport.md[/dim]"
    )


# ---------------------------------------------------------------------------


def _parse_severity(value: str) -> Severity:
    try:
        return Severity(value.strip().lower())
    except ValueError:
        valid = ", ".join(severity.value for severity in Severity)
        err_console.print(f"[red]Gravité « {value} » inconnue. Valeurs acceptées : {valid}.[/red]")
        raise typer.Exit(code=64) from None


def _write(path: Path, content: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        err_console.print(f"[red]Écriture impossible dans {path} : {exc}[/red]")
        raise typer.Exit(code=73) from None


def _check_dns(settings: object) -> tuple[Text, str]:
    from .config import Settings
    from .net.resolver import DnsResolver

    assert isinstance(settings, Settings)
    try:
        resolver = DnsResolver(settings)
        record = resolver.query("example.com", "A")
    except Exception as exc:  # pragma: no cover - dépend de l'environnement
        return Text("absent", style="red"), f"échec : {type(exc).__name__}"

    resolvers = ", ".join(settings.resolvers)
    if record.ok and record.values:
        return Text("OK", style="green"), f"via {resolvers}"
    if resolver.doh_used:
        return Text("dégradé", style="yellow"), "port 53 filtré, repli DNS-over-HTTPS actif"
    return Text("absent", style="red"), f"aucune réponse de {resolvers}"


def _check_http(settings: object, url: str) -> tuple[Text, str]:
    from .config import Settings
    from .net.http import HttpClient

    assert isinstance(settings, Settings)
    try:
        with HttpClient(settings) as http:
            payload = http.get_json(url)
    except Exception as exc:  # pragma: no cover - dépend de l'environnement
        return Text("absent", style="red"), f"échec : {type(exc).__name__}"

    if payload:
        return Text("OK", style="green"), "service interrogeable"
    return Text("dégradé", style="yellow"), "aucune réponse exploitable"


@app.command("test-spoof")
def test_spoof_command(
    target: str = typer.Argument(..., help="Domaine dont on teste l'usurpation."),
    scenario: list[str] = typer.Option(
        [], "--scenario", "-s", help="Limiter à certains scénarios (répétable)."
    ),
    mode: str = typer.Option("", "--mode", help="Chemin d'envoi : direct | relay (défaut : .env)."),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Construit et affiche les messages sans rien envoyer."
    ),
    cleanup: bool = typer.Option(
        False, "--cleanup", help="Supprime les messages-tests de la boîte après vérification."
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Écrit le rapport Markdown de la campagne."
    ),
) -> None:
    """Teste si un tiers peut usurper un domaine vers ta boîte de vérification.

    Forge des messages au nom du domaine cible, les livre à la boîte contrôlée
    (prouvée par IMAP), puis observe ce que le serveur récepteur en fait.
    """
    settings = load_settings()
    mail_config = load_mail_test_config()
    if mode:
        mail_config.send.mode = mode.strip().lower()

    selected = spoof_scenarios.get_scenarios(tuple(scenario)) if scenario else None
    if scenario and not selected:
        err_console.print(
            "[red]Aucun scénario ne correspond. Disponibles : "
            + ", ".join(s.id for s in spoof_scenarios.DEFAULT_SCENARIOS)
            + "[/red]"
        )
        raise typer.Exit(code=64)

    def progress(stage: str, detail: str) -> None:
        console.print(f"  [dim]{stage:>7}[/dim]  {detail}")

    try:
        campaign = run_spoof_campaign(
            mail_config,
            target,
            settings=settings,
            selected=selected,
            dry_run=dry_run,
            cleanup=cleanup,
            on_progress=progress,
        )
    except SafetyError as exc:
        err_console.print(f"\n[bold red]Refus de sûreté[/bold red] — {exc}")
        raise typer.Exit(code=2) from None

    console.print()
    active_report.print_campaign(console, campaign)

    if output:
        _write(output, active_report.campaign_markdown(campaign))
        console.print(f"\n[green]Rapport écrit :[/green] {output}")

    # Code de sortie non nul si une usurpation a atteint la boîte de réception.
    if campaign.breaches:
        raise typer.Exit(code=3)


@app.command("probe-mx")
def probe_mx_command(
    domain: str = typer.Argument(..., help="Domaine dont on sonde les serveurs MX."),
    timeout: float = typer.Option(15.0, "--timeout", help="Délai par MX, en secondes."),
) -> None:
    """Sonde le transport des MX (STARTTLS, certificat, AUTH) sans envoyer de mail."""
    settings = load_settings()
    resolver = DnsResolver(settings)
    with console.status(f"Sonde des MX de {domain}…", spinner="dots"):
        results = mx_probe.probe_domain(resolver, domain, timeout=timeout)
    active_report.print_mx_probe(console, domain, results)


@app.command("mail-doctor")
def mail_doctor_command() -> None:
    """Vérifie la configuration des tests actifs (IMAP, envoi, consentement)."""
    from .active import imap_verify

    mail_config = load_mail_test_config()
    mailbox = mail_config.mailbox

    table = Table(title="Configuration des tests actifs", title_justify="left")
    table.add_column("Élément")
    table.add_column("État")
    table.add_column("Détail")

    ok = Text("OK", style="green")
    missing = Text("manquant", style="red")
    warn = Text("à vérifier", style="yellow")

    table.add_row(
        "Boîte de vérification",
        ok if mailbox.address else missing,
        mailbox.address or "DA_TEST_MAILBOX / DA_IMAP_USER",
    )
    table.add_row(
        "Serveur IMAP",
        ok if mailbox.imap_host else missing,
        f"{mailbox.imap_host}:{mailbox.imap_port}" if mailbox.imap_host else "DA_IMAP_HOST",
    )
    table.add_row(
        "Mot de passe IMAP",
        ok if mailbox.imap_password else missing,
        "présent" if mailbox.imap_password else "DA_IMAP_PASSWORD",
    )
    table.add_row(
        "Consentement (DA_TEST_ACK)",
        ok if mail_config.acknowledged else missing,
        "confirmé" if mail_config.acknowledged else "mets DA_TEST_ACK=true",
    )
    table.add_row(
        "Chemin d'envoi",
        ok,
        f"{mail_config.send.mode}"
        + (f" via {mail_config.send.relay_host}" if mail_config.send.mode == "relay" else " (port 25)"),
    )

    # Preuve de possession en direct, si la config est complète.
    if mailbox.configured:
        with console.status("Connexion IMAP (preuve de possession)…", spinner="dots"):
            proven = imap_verify.verify_login(mailbox)
        table.add_row(
            "Preuve de possession",
            ok if proven else missing,
            "connexion IMAP réussie" if proven else "connexion IMAP refusée",
        )
    else:
        table.add_row("Preuve de possession", warn, "config incomplète, test non effectué")

    console.print(table)
    if mailbox.configured and mail_config.acknowledged:
        console.print("\n[green]Prêt.[/green] Exemple : [bold]da test-spoof capibara.fr[/bold]")
    else:
        console.print(
            "\n[yellow]Complète le .env[/yellow] (DA_IMAP_* + DA_TEST_ACK) avant de lancer une campagne."
        )


def main() -> None:
    """Point d'entrée des scripts installés."""
    app()


if __name__ == "__main__":
    main()
