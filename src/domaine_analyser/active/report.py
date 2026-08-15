"""Restitution des campagnes de tests actifs et des sondes MX."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import CampaignResult, Disposition, MxTlsResult

_DISPOSITION_STYLE = {
    Disposition.DELIVERED: "bold red",
    Disposition.QUARANTINE: "yellow",
    Disposition.DROPPED: "green",
    Disposition.REJECTED: "bold green",
    Disposition.DEFERRED: "cyan",
    Disposition.PENDING: "dim",
    Disposition.NOT_SENT: "magenta",
    Disposition.DRY_RUN: "dim",
}


# ---------------------------------------------------------------------------
# Terminal
# ---------------------------------------------------------------------------


def print_campaign(console: Console, campaign: CampaignResult) -> None:
    breaches = campaign.breaches
    if breaches:
        header = Text()
        header.append(f"Usurpation de {campaign.target}\n", style="bold")
        header.append(f"{len(breaches)} scénario(s) ont atteint la boîte de réception", style="bold red")
        border = "red"
    else:
        header = Text()
        header.append(f"Usurpation de {campaign.target}\n", style="bold")
        header.append("Aucun message forgé n'a atteint la boîte de réception", style="bold green")
        border = "green"

    policy = campaign.target_policy or "inconnue"
    header.append(f"\nPolitique DMARC de la cible : p={policy}", style="dim")
    header.append(f"\nBoîte de réception testée : {campaign.mailbox_address}", style="dim")
    console.print(Panel(header, border_style=border, padding=(1, 2)))

    table = Table(show_lines=True)
    table.add_column("Scénario", no_wrap=True)
    table.add_column("From: forgé")
    table.add_column("Résultat", no_wrap=True)
    table.add_column("Verdict récepteur", no_wrap=True)

    for r in campaign.results:
        style = _DISPOSITION_STYLE.get(r.disposition, "white")
        auth = r.delivery.auth
        verdict = (
            ", ".join(
                f"{k}={v}"
                for k, v in (("spf", auth.spf), ("dkim", auth.dkim), ("dmarc", auth.dmarc))
                if v
            )
            or "—"
        )
        table.add_row(
            r.scenario.name,
            Text(r.message.from_header, overflow="ellipsis"),
            Text(r.disposition.label_fr, style=style),
            verdict,
        )
    console.print(table)

    console.print()
    for r in campaign.results:
        console.print(f"[dim]›[/dim] [bold]{r.scenario.name}[/bold] — {r.interpretation}")

    for note in campaign.notes:
        console.print(f"[dim]· {note}[/dim]")


def print_mx_probe(console: Console, domain: str, results: list[MxTlsResult]) -> None:
    console.print(f"[bold]Sonde de transport — {domain}[/bold]\n")
    if not results:
        console.print("[yellow]Aucun MX à sonder.[/yellow]")
        return

    for r in results:
        if r.error and not r.connected:
            console.print(f"[red]✗[/red] {r.mx_host} (pref {r.preference}) — {r.error}")
            continue

        tls = "non proposé"
        if r.starttls_offered:
            match = "cert OK" if r.cert_matches_host else "cert ne correspond pas à l'hôte"
            tls = f"{r.tls_version or 'négocié'}, {match}"
        style = "green" if r.starttls_offered and r.cert_matches_host else "yellow"
        console.print(f"[{style}]●[/{style}] [bold]{r.mx_host}[/bold] (pref {r.preference})")
        console.print(f"    bannière : {r.banner or '—'}")
        console.print(f"    STARTTLS : {tls}")
        if r.cert_subject:
            console.print(f"    certificat : {r.cert_subject}  (émis par {r.cert_issuer})")
            console.print(f"    expire : {r.cert_not_after}")
        if r.auth_mechanisms:
            console.print(f"    AUTH annoncé : {', '.join(r.auth_mechanisms)}")
        if r.error:
            console.print(f"    [yellow]note : {r.error}[/yellow]")


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def campaign_markdown(campaign: CampaignResult) -> str:
    lines = [
        f"# Test d'usurpation — {campaign.target}",
        "",
        f"- Boîte de réception testée : `{campaign.mailbox_address}`",
        f"- Politique DMARC de la cible : `p={campaign.target_policy or 'inconnue'}`",
        f"- Lancé le : {campaign.started_at.strftime('%d/%m/%Y %H:%M UTC')}",
        f"- Scénarios ayant atteint la boîte de réception : **{len(campaign.breaches)}**",
        "",
        "| Scénario | From: forgé | Résultat | Verdict récepteur |",
        "| --- | --- | --- | --- |",
    ]
    for r in campaign.results:
        auth = r.delivery.auth
        verdict = (
            ", ".join(
                f"{k}={v}"
                for k, v in (("spf", auth.spf), ("dkim", auth.dkim), ("dmarc", auth.dmarc))
                if v
            )
            or "—"
        )
        frm = r.message.from_header.replace("|", "\\|")
        lines.append(
            f"| {r.scenario.name} | `{frm}` | {r.disposition.label_fr} | {verdict} |"
        )

    lines += ["", "## Lecture des résultats", ""]
    for r in campaign.results:
        lines += [f"### {r.scenario.name}", "", f"- **Objectif.** {r.scenario.goal}"]
        if r.smtp.mx_host:
            code = r.smtp.code if r.smtp.code is not None else "—"
            lines.append(f"- **SMTP.** MX `{r.smtp.mx_host}`, code {code}.")
        if r.smtp.error:
            lines.append(f"- **Envoi.** {r.smtp.error}")
        if r.delivery.arrived:
            lines.append(f"- **Dépôt.** dossier `{r.delivery.folder}`.")
        lines += [f"- **Verdict.** {r.interpretation}", ""]

    if campaign.notes:
        lines += ["## Notes", ""]
        lines += [f"- {n}" for n in campaign.notes]

    lines += [
        "",
        "---",
        "",
        "_Auto-test d'usurpation DomaineAnalyser. Messages livrés uniquement à la "
        "boîte contrôlée, dont la possession est prouvée par connexion IMAP._",
    ]
    return "\n".join(lines) + "\n"
