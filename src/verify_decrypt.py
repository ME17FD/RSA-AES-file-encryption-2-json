"""Vérifie la signature reçue et déchiffre le paquet sécurisé."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from crypto_utils import (
    SecurePackage,
    SignatureVerificationError,
    decrypt_aes_cbc,
    decrypt_rsa_oaep,
    load_private_key,
    load_public_key,
    PublicKeyImportError,
    verify_signature,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Déchiffre un paquet sécurisé et vérifie la signature de l'expéditeur.",
    )
    parser.add_argument(
        "--package",
        type=Path,
        required=True,
        help="Paquet sécurisé JSON reçu.",
    )
    parser.add_argument(
        "--recipient-private-key",
        type=Path,
        required=True,
        help="Clé privée RSA du destinataire (PEM).",
    )
    parser.add_argument(
        "--sender-public-key",
        type=Path,
        required=True,
        help="Clé publique RSA de l'expéditeur (PEM).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Chemin du fichier en clair à écrire (sinon même dossier que le paquet).",
    )
    parser.add_argument(
        "--passphrase",
        default=None,
        help="Mot de passe de la clé privée si elle est protégée.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    try:
        package = SecurePackage.load_json(args.package)
    except (json.JSONDecodeError, TypeError, KeyError, ValueError) as exc:
        raise SystemExit(
            " Le fichier JSON du paquet est invalide ou ne contient pas les champs attendus."
        ) from exc
    encrypted_key, iv, ciphertext, signature = package.as_binary_components()

    recipient_private_key = load_private_key(args.recipient_private_key, passphrase=args.passphrase)

    try:
        sender_public_key = load_public_key(args.sender_public_key)
    except PublicKeyImportError as exc:
        raise SystemExit(
            " La clé publique de l'expéditeur est invalide ou a été modifiée. "
            "Vérifiez que vous utilisez la bonne clé."
        ) from exc

    try:
        aes_key = decrypt_rsa_oaep(recipient_private_key, encrypted_key)
    except ValueError as exc:
        raise SystemExit(
            " Impossible de déchiffrer la clé AES : mauvaise clé privée ou paquet corrompu."
        ) from exc

    try:
        plaintext = decrypt_aes_cbc(ciphertext, aes_key, iv)
    except ValueError as exc:  # padding invalide => fichier trafiqué ou mauvaise clé
        raise SystemExit(
            " Le déchiffrement AES a échoué (données altérées ou clé incorrecte)."
        ) from exc

    try:
        verify_signature(sender_public_key, plaintext, signature)
    except SignatureVerificationError as exc:
        raise SystemExit(" Signature invalide : le fichier a peut-être été modifié.") from exc

    output_path = args.output or args.package.with_name(package.filename)
    output_path.write_bytes(plaintext)

    print(" Tout est bon !")
    print(f"  . Fichier déchiffré : {output_path}")
    print("  . Signature vérifiée, le message n'a pas été altéré.")


if __name__ == "__main__":
    main()

