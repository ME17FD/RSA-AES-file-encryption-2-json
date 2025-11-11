"""Petit script interactif pour taper un message, le signer et le chiffrer."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional

from crypto_utils import (
    SecurePackage,
    encrypt_aes_cbc,
    encrypt_rsa_oaep,
    export_private_key,
    export_public_key,
    generate_rsa_keypair,
    load_private_key,
    load_public_key,
    sign_bytes,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Demande un nom de fichier + contenu, puis signe et chiffre tout ça.",
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
        "--package",
        type=Path,
        default=Path("message_secure.json"),
        help="Nom du paquet JSON produit (défaut : message_secure.json).",
    )
    parser.add_argument(
        "--passphrase",
        default=None,
        help="Mot de passe pour la clé privée si elle est chiffrée.",
    )
    parser.add_argument(
        "--save-plaintext",
        action="store_true",
        help="Sauvegarde aussi le fichier en clair localement.",
    )
    return parser.parse_args()


def _derive_public_key_path(private_key_path: Path) -> Path:
    if private_key_path.suffix:
        base = private_key_path.stem
        suffix = private_key_path.suffix
    else:
        base = private_key_path.name
        suffix = ""
    if base.endswith("_private"):
        base = base[:-8] + "_public"
    else:
        base = base + "_public"
    return private_key_path.with_name(base + (suffix or ".pem"))


def _derive_private_key_path(public_key_path: Path) -> Path:
    if public_key_path.suffix:
        base = public_key_path.stem
        suffix = public_key_path.suffix
    else:
        base = public_key_path.name
        suffix = ""
    if base.endswith("_public"):
        base = base[:-7] + "_private"
    else:
        base = base + "_private"
    return public_key_path.with_name(base + (suffix or ".pem"))


def ensure_sender_private_key(path: Path, passphrase: Optional[str]) -> Path:
    if path.exists():
        return path

    path.parent.mkdir(parents=True, exist_ok=True)
    key = generate_rsa_keypair()
    export_private_key(key, path, passphrase=passphrase)
    public_path = _derive_public_key_path(path)
    export_public_key(key.public_key(), public_path)
    print(" Aucune clé privée expéditeur trouvée, on en génère une nouvelle :")
    print(f"  • Clé privée : {path}")
    print(f"  • Clé publique : {public_path}")
    return path


def ensure_recipient_public_key(path: Path) -> Path:
    if path.exists():
        return path

    path.parent.mkdir(parents=True, exist_ok=True)
    key = generate_rsa_keypair()
    private_path = _derive_private_key_path(path)
    export_public_key(key.public_key(), path)
    export_private_key(key, private_path)
    print(" Pas de clé publique destinataire détectée, génération d'un nouveau couple :")
    print(f"  • Clé publique : {path}")
    print(f"  • Clé privée (à garder secrète) : {private_path}")
    print("  ➜ Partage cette nouvelle clé publique avec l'expéditeur.")
    return path


def capture_plaintext() -> tuple[str, bytes]:
    filename = ""
    while not filename:
        filename = input("Nom du fichier (ex: message.txt) : ").strip()
        if not filename:
            print("  Le nom ne peut pas être vide.")

    print("Écris ton texte ci-dessous. Tape juste 'EOF' sur une ligne pour terminer :")
    lines: list[str] = []
    while True:
        try:
            line = input()
        except EOFError:
            break  # pour gérer un Ctrl+D / Ctrl+Z si on veut terminer autrement
        if line == "EOF":
            break
        lines.append(line)
    plaintext = "\n".join(lines).encode("utf-8")
    return filename, plaintext


def main() -> None:
    args = parse_args()

    sender_private_key_path = ensure_sender_private_key(args.sender_private_key, args.passphrase)
    recipient_public_key_path = ensure_recipient_public_key(args.recipient_public_key)

    filename, plaintext = capture_plaintext()

    sender_private_key = load_private_key(sender_private_key_path, passphrase=args.passphrase)
    recipient_public_key = load_public_key(recipient_public_key_path)

    signature = sign_bytes(sender_private_key, plaintext)
    ciphertext, aes_key, iv = encrypt_aes_cbc(plaintext)
    encrypted_key = encrypt_rsa_oaep(recipient_public_key, aes_key)

    package = SecurePackage.from_components(
        encrypted_key=encrypted_key,
        iv=iv,
        ciphertext=ciphertext,
        signature=signature,
        filename=filename,
    )
    package.to_json(args.package)

    if args.save_plaintext:
        Path(filename).write_bytes(plaintext)
        print(f"  Fichier en clair enregistré : {filename}")

    print(" Paquet sécurisé créé !")
    print(f"  • JSON : {args.package}")
    print("  • À transmettre au destinataire (avec ta clé publique).")


if __name__ == "__main__":
    main()

