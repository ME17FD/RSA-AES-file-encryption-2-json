"""Script simple pour générer une paire de clés RSA pour le projet."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional

from crypto_utils import export_private_key, export_public_key, generate_rsa_keypair


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Génère une paire de clés RSA-2048 pour signer et chiffrer.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("keys"),
        help="Dossier où enregistrer les clés (créé automatiquement si besoin).",
    )
    parser.add_argument(
        "--prefix",
        default="id_rsa",
        help="Préfixe des fichiers générés (ex: id_rsa -> id_rsa_private.pem).",
    )
    parser.add_argument(
        "--passphrase",
        default=None,
        help="Mot de passe optionnel pour chiffrer la clé privée (PKCS#8 + scrypt+AES128).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_dir: Path = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    private_key = generate_rsa_keypair()
    private_path = output_dir / f"{args.prefix}_private.pem"
    public_path = output_dir / f"{args.prefix}_public.pem"

    passphrase: Optional[str] = args.passphrase
    export_private_key(private_key, private_path, passphrase=passphrase)
    export_public_key(private_key.public_key(), public_path)

    print(" Paire de clés générée !")
    print(f"  . Clé privée : {private_path}")
    print(f"  . Clé publique : {public_path}")
    if passphrase:
        print("  Garde bien le mot de passe, il sera demandé pour utiliser la clé privée.")


if __name__ == "__main__":
    main()

