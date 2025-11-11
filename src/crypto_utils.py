"""Fonctions utilitaires partagées pour le mini-projet d'échange de fichiers sécurisé."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad


AES_KEY_BYTES = 16  # AES-128
AES_BLOCK_BYTES = 16
RSA_KEY_BITS = 2048


class SignatureVerificationError(RuntimeError):
    """Exception levée quand la signature RSA ne correspond pas."""


class PublicKeyImportError(RuntimeError):
    """Exception levée quand la clé publique fournie est invalide."""


def generate_rsa_keypair(bits: int = RSA_KEY_BITS) -> RSA.RsaKey:
    """Génère une clé privée RSA de la taille voulue."""
    return RSA.generate(bits)


def export_private_key(
    private_key: RSA.RsaKey,
    path: Path,
    passphrase: Optional[str] = None,
) -> None:
    """Sauvegarde la clé privée RSA au format PEM."""
    kwargs = {}
    if passphrase:
        kwargs.update(
            {
                "passphrase": passphrase,
                "pkcs": 8,
                "protection": "scryptAndAES128-CBC",
            }
        )
    pem = private_key.export_key(**kwargs)
    path.write_bytes(pem)


def export_public_key(public_key: RSA.RsaKey, path: Path) -> None:
    """Sauvegarde la clé publique RSA au format PEM."""
    path.write_bytes(public_key.export_key())


def load_private_key(path: Path, passphrase: Optional[str] = None) -> RSA.RsaKey:
    """Charge une clé privée RSA depuis un fichier."""
    return RSA.import_key(path.read_bytes(), passphrase=passphrase)


def load_public_key(path: Path) -> RSA.RsaKey:
    """Charge une clé publique RSA depuis un fichier."""
    try:
        return RSA.import_key(path.read_bytes())
    except ValueError as exc:
        raise PublicKeyImportError(
            "La clé publique n'est pas au format RSA attendu."
        ) from exc


def sign_bytes(private_key: RSA.RsaKey, data: bytes) -> bytes:
    """Signe des données avec RSA (PKCS#1 v1.5) et SHA-256."""
    digest = SHA256.new(data)
    return pkcs1_15.new(private_key).sign(digest)


def verify_signature(public_key: RSA.RsaKey, data: bytes, signature: bytes) -> None:
    """Vérifie une signature RSA. Lève une erreur si elle est fausse."""
    try:
        pkcs1_15.new(public_key).verify(SHA256.new(data), signature)
    except (ValueError, TypeError) as exc:  # PyCryptodome raises ValueError
        raise SignatureVerificationError("Signature verification failed.") from exc


def encrypt_aes_cbc(plaintext: bytes, key: Optional[bytes] = None) -> tuple[bytes, bytes, bytes]:
    """Chiffre un message avec AES-128 en mode CBC. Renvoie (ciphertext, key, iv)."""
    key = key or get_random_bytes(AES_KEY_BYTES)
    iv = get_random_bytes(AES_BLOCK_BYTES)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES_BLOCK_BYTES))
    return ciphertext, key, iv


def decrypt_aes_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Déchiffre un message AES-128-CBC."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    return unpad(padded_plaintext, AES_BLOCK_BYTES)


def encrypt_rsa_oaep(public_key: RSA.RsaKey, data: bytes) -> bytes:
    """Chiffre des octets avec RSA OAEP (SHA-256)."""
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    return cipher.encrypt(data)


def decrypt_rsa_oaep(private_key: RSA.RsaKey, data: bytes) -> bytes:
    """Déchiffre des octets avec RSA OAEP (SHA-256)."""
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    return cipher.decrypt(data)


@dataclass
class SecurePackage:
    """
    Objet simple qui regroupe tout ce qu'on envoie (clé AES chiffrée, IV, données, signature).

    On stocke les champs binaires en base64 pour que le JSON reste lisible et portable.
    """

    encrypted_key: str
    iv: str
    ciphertext: str
    signature: str
    filename: str
    metadata: dict[str, str]

    @classmethod
    def from_components(
        cls,
        *,
        encrypted_key: bytes,
        iv: bytes,
        ciphertext: bytes,
        signature: bytes,
        filename: str,
    ) -> "SecurePackage":
        """Construit un paquet sécurisé à partir des éléments binaires."""
        metadata = {
            "hash": "SHA-256",
            "signature_scheme": "RSA-PKCS1v1.5",
            "symmetric_encryption": "AES-128-CBC",
            "asymmetric_encryption": "RSA-2048-OAEP",
        }
        return cls(
            encrypted_key=base64.b64encode(encrypted_key).decode("ascii"),
            iv=base64.b64encode(iv).decode("ascii"),
            ciphertext=base64.b64encode(ciphertext).decode("ascii"),
            signature=base64.b64encode(signature).decode("ascii"),
            filename=filename,
            metadata=metadata,
        )

    def to_json(self, path: Path) -> None:
        """Écrit le paquet dans un fichier JSON."""
        path.write_text(json.dumps(asdict(self), indent=2))

    @classmethod
    def load_json(cls, path: Path) -> "SecurePackage":
        """Recharge un paquet sécurisé depuis un fichier JSON."""
        data = json.loads(path.read_text())
        return cls(**data)

    def as_binary_components(self) -> tuple[bytes, bytes, bytes, bytes]:
        """Renvoie les champs binaires décodés (clé chiffrée, IV, ciphertext, signature)."""
        return tuple(
            base64.b64decode(value)
            for value in (self.encrypted_key, self.iv, self.ciphertext, self.signature)
        )


