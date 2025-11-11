"""Signe un fichier puis le chiffre en mode hybride (RSA + AES)."""

from __future__ import annotations

import argparse
from pathlib import Path

from crypto_utils import (
    SecurePackage,
    encrypt_aes_cbc,
    encrypt_rsa_oaep,
    load_private_key,
    load_public_key,
    sign_bytes,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Signe un fichier et le chiffre avec RSA/AES (mode hybride).",
    )
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Chemin du fichier en clair à protéger.",
    )
    parser.add_argument(
        "--sender-private-key",
        type=Path,
        required=True,
        help="Clé privée RSA de l'expéditeur (PEM).",
    )
    parser.add_argument(
        "--recipient-public-key",
        type=Path,
        required=True,
        help="Clé publique RSA du destinataire (PEM).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Fichier de sortie contenant le paquet sécurisé (JSON).",
    )
    parser.add_argument(
        "--passphrase",
        default=None,
        help="Mot de passe de la clé privée si elle est protégée.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    plaintext = args.input.read_bytes()
    sender_private_key = load_private_key(args.sender_private_key, passphrase=args.passphrase)
    recipient_public_key = load_public_key(args.recipient_public_key)

    signature = sign_bytes(sender_private_key, plaintext)
    ciphertext, aes_key, iv = encrypt_aes_cbc(plaintext)
    encrypted_key = encrypt_rsa_oaep(recipient_public_key, aes_key)

    package = SecurePackage.from_components(
        encrypted_key=encrypted_key,
        iv=iv,
        ciphertext=ciphertext,
        signature=signature,
        filename=args.input.name,
    )
    package.to_json(args.output)

    print(" Paquet sécurisé prêt !")
    print(f"  . Fichier JSON : {args.output}")
    print("  . Contient la signature, la clé AES chiffrée, l'IV et le ciphertext.")
    print("Envoie ce JSON au destinataire ainsi que ta clé publique.")


if __name__ == "__main__":
    main()

