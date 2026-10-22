"""The two keys a Hippius access key (a BIP-39 phrase) stands for.

The console's access-key sign-in derives both from the same phrase, and the
API checks both, so a headless login has to match it byte for byte:

* sr25519, as polkadot.js ``Keyring({type: "sr25519"}).addFromMnemonic``:
  mini secret = PBKDF2-HMAC-SHA512(entropy, "mnemonic", 2048)[:32], no
  derivation path, SS58 prefix 42. Signs the raw UTF-8 message.
* secp256k1, as viem ``mnemonicToAccount``: BIP-32 path m/44'/60'/0'/0/0 on
  the BIP-39 seed, EIP-55 address, EIP-191 ``personal_sign``.

Needs the ``login`` extra: ``pip install 'hippius-drive[login]'``.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib
from dataclasses import dataclass, field
from typing import Any

from mnemonic import Mnemonic

try:
    from coincurve import PrivateKey
    from Crypto.Hash import keccak

    # The bindings ship no type information; bind the module as Any.
    sr25519: Any = importlib.import_module("sr25519")
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        "access-key login needs the login extra: pip install 'hippius-drive[login]'"
    ) from exc

SS58_PREFIX = 42
EVM_PATH = (44 | 0x80000000, 60 | 0x80000000, 0 | 0x80000000, 0, 0)
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_HARDENED = 0x80000000
_BIP39 = Mnemonic("english")
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


@dataclass(frozen=True)
class WalletKeys:
    """Both keys behind one access key. The secrets stay out of ``repr``.

    Attributes:
        ss58_address: The sr25519 account, SS58 prefix 42. The account address.
        evm_address: The EIP-55 secp256k1 address.
    """

    ss58_address: str
    evm_address: str
    _sr25519: tuple[bytes, bytes] = field(repr=False)
    _evm_secret: bytes = field(repr=False)

    def sign_sr25519(self, message: str) -> str:
        """Return ``0x`` + hex of an sr25519 signature over the UTF-8 message."""
        return "0x" + sr25519.sign(self._sr25519, message.encode()).hex()

    def sign_evm(self, message: str) -> str:
        """Return ``0x`` + hex of an EIP-191 ``personal_sign`` signature (v = 27/28)."""
        raw = PrivateKey(self._evm_secret).sign_recoverable(eip191_hash(message), hasher=None)
        if raw[64] > 1:  # pragma: no cover - recovery id 2/3: x >= n, probability ~2^-127
            raise ValueError("signature has a recovery id Ethereum cannot express; sign again")
        return "0x" + raw[:64].hex() + f"{raw[64] + 27:02x}"


def wallet_keys(phrase: str) -> WalletKeys:
    """Derive both keys from an access key.

    Args:
        phrase: The BIP-39 phrase, 12 or 24 words. Runs of whitespace count as
            one space; polkadot.js refuses them, this derives what it derives
            for the cleanly spaced phrase.

    Returns:
        The addresses and signing keys.

    Raises:
        ValueError: If the phrase is not valid BIP-39.
    """
    normalized = " ".join(phrase.split())
    if not _BIP39.check(normalized):
        raise ValueError("invalid BIP-39 mnemonic (bad word or checksum)")
    entropy = bytes(_BIP39.to_entropy(normalized))
    mini = hashlib.pbkdf2_hmac("sha512", entropy, b"mnemonic", 2048)[:32]
    public, secret = sr25519.pair_from_seed(mini)
    evm_secret = _bip32_secret(Mnemonic.to_seed(normalized), EVM_PATH)
    return WalletKeys(
        ss58_address=ss58_encode(public),
        evm_address=evm_address(evm_secret),
        _sr25519=(public, secret),
        _evm_secret=evm_secret,
    )


def ss58_encode(public_key: bytes, prefix: int = SS58_PREFIX) -> str:
    """SS58-encode a 32-byte public key with a one-byte network prefix."""
    if len(public_key) != 32 or not 0 <= prefix < 64:  # noqa: PLR2004
        raise ValueError("ss58 needs a 32-byte key and a one-byte prefix")
    body = bytes([prefix]) + public_key
    checksum = hashlib.blake2b(b"SS58PRE" + body, digest_size=64).digest()[:2]
    return _base58(body + checksum)


def evm_address(secret: bytes) -> str:
    """The EIP-55 address of a secp256k1 secret key."""
    public = PrivateKey(secret).public_key.format(compressed=False)[1:]
    raw = _keccak(public)[-20:].hex()
    digest = _keccak(raw.encode()).hex()
    return "0x" + "".join(
        char.upper() if int(digest[i], 16) >= 8 else char  # noqa: PLR2004
        for i, char in enumerate(raw)
    )


def eip191_hash(message: str) -> bytes:
    """The EIP-191 personal_sign digest of ``message``."""
    data = message.encode()
    return _keccak(b"\x19Ethereum Signed Message:\n" + str(len(data)).encode() + data)


def _bip32_secret(seed: bytes, path: tuple[int, ...]) -> bytes:
    master = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    key, chain = master[:32], master[32:]
    if not 0 < int.from_bytes(key, "big") < _SECP256K1_N:  # pragma: no cover - ~2^-127
        raise ValueError("BIP-32 master key is invalid for this phrase")
    for index in path:
        key, chain = _bip32_child(key, chain, index)
    return key


def _bip32_child(key: bytes, chain: bytes, index: int) -> tuple[bytes, bytes]:
    """CKDpriv; an invalid child moves on to the next index, as BIP-32 says."""
    while True:
        if index & _HARDENED:
            data = b"\x00" + key + index.to_bytes(4, "big")
        else:
            data = PrivateKey(key).public_key.format(compressed=True) + index.to_bytes(4, "big")
        digest = hmac.new(chain, data, hashlib.sha512).digest()
        tweak = int.from_bytes(digest[:32], "big")
        child = (tweak + int.from_bytes(key, "big")) % _SECP256K1_N
        if tweak < _SECP256K1_N and child != 0:
            return child.to_bytes(32, "big"), digest[32:]
        index += 1  # pragma: no cover - probability ~2^-127


def _keccak(data: bytes) -> bytes:
    return keccak.new(digest_bits=256, data=data).digest()


def _base58(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, rest = divmod(number, 58)
        encoded = _B58[rest] + encoded
    leading = len(data) - len(data.lstrip(b"\x00"))
    return "1" * leading + encoded
