"""`python -m zanshin.agent` — the command an operator actually runs."""
import argparse
import logging
import signal
import sys

from zanshin.agent.config import from_environment
from zanshin.agent.worker import AgentWorker

logger = logging.getLogger("zanshin.agent")

EPILOG = """\
Exemple :

  ZANSHIN_URL=https://zanshin.interne \\
  ZANSHIN_AGENT_TOKEN=zsk_... \\
  python -m zanshin.agent

La clé doit porter la portée « agent » : créez l'agent depuis la page Agents de
Zanshin, qui émet la clé avec lui et ne l'affiche qu'une fois.

Cet agent a besoin de Docker (ou d'un service scan-api joignable), et d'un accès
git aux dépôts scannés — par défaut avec ses propres identifiants, aucune clé
n'étant transmise par le contrôleur.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m zanshin.agent",
        description="Agent d'exécution de scans Zanshin.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--url", help="URL du contrôleur Zanshin (ou ZANSHIN_URL).")
    parser.add_argument("--token", help="Clé API à portée « agent » (ou ZANSHIN_AGENT_TOKEN).")
    parser.add_argument(
        "--scanner-engine",
        choices=("docker", "local_api", "osv"),
        help="Où s'exécutent les outils sur cette machine (défaut : docker).",
    )
    parser.add_argument("--local-api-url", help="URL du sidecar scan-api, si --scanner-engine=local_api.")
    parser.add_argument("--local-api-shared-dir", help="Répertoire partagé avec le sidecar scan-api.")
    parser.add_argument("--name", help="Nom d'hôte à déclarer (défaut : le hostname réel).")
    parser.add_argument(
        "--max-jobs",
        type=int,
        help="S'arrêter après ce nombre de scans (utile comme étape de CI).",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Ne pas vérifier le certificat TLS du contrôleur. À éviter.",
    )
    parser.add_argument("--verbose", action="store_true", help="Journalisation détaillée.")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

    try:
        config = from_environment(
            url=args.url,
            token=args.token,
            scanner_engine=args.scanner_engine,
            local_api_url=args.local_api_url,
            local_api_shared_dir=args.local_api_shared_dir,
            name=args.name,
            max_jobs=args.max_jobs,
            verify_tls=False if args.insecure else None,
        )
    except ValueError as e:
        # A configuration mistake, not a crash: print what is missing and stop.
        print(f"Configuration invalide : {e}", file=sys.stderr)
        return 2

    if not config.is_secure:
        # Said once, at startup, rather than on every request: the agent works over
        # plain HTTP (a trusted network is a legitimate deployment), but the
        # controller will refuse to send deploy keys over it, and an operator who
        # picked the delegated mode needs to know that before wondering why clones
        # fail.
        logger.warning(
            "Le contrôleur est joint en HTTP : aucune clé de déploiement ne sera "
            "transmise à cet agent (voir le mode « délégué » dans la documentation)."
        )

    worker = AgentWorker(config)

    def shutdown(_signum, _frame):
        logger.info("Arrêt demandé ; l'agent termine le scan en cours puis s'arrête.")
        worker.stop()

    # SIGTERM is what a container orchestrator sends: without this the agent is
    # killed mid-scan and the controller has to wait out the lease.
    for received in (signal.SIGINT, signal.SIGTERM):
        signal.signal(received, shutdown)

    handled = worker.run_forever()
    logger.info("Agent arrêté après %d scan(s).", handled)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
