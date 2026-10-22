"""Access-key key derivation, pinned to what the console and the API compute.

The addresses and the EIP-191 signature were checked against eth-account and
substrate-interface, the libraries the API verifies with: the same address,
a byte-identical (RFC 6979) secp256k1 signature, and an sr25519 signature
``Keypair.verify`` accepts.
"""

from __future__ import annotations

import importlib
from typing import Any

import pytest
from coincurve import PrivateKey, PublicKey

from hippius_drive.crypto import wallet

# Published BIP-39 and Substrate test phrases. Not wallets.
ABANDON = " ".join(["abandon"] * 11 + ["about"])
DEV = "bottom drive obey lake curtain smoke basket hold race lonely fit walk"
MESSAGE = "Please sign this message to verify your ownership: " + "ab" * 32
FROZEN_EVM_SIGNATURE = (
    "0xdc9452f02b4ddf3a21543fdea9a0452377119f39d51551945cc15a73cefbb058"
    "313404bae1d1c47969fe7d777d807eddd1f9c38f31a7b2c2f297b8551dd90bf81c"
)
sr25519: Any = importlib.import_module("sr25519")


def test_the_addresses_match_the_known_vectors() -> None:
    keys = wallet.wallet_keys(ABANDON)
    assert keys.ss58_address == "5EPCUjPxiHAcNooYipQFWr9NmmXJKpNG5RhcntXwbtUySrgH"
    assert keys.evm_address == "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
    # Substrate's dev phrase with no derivation path, as polkadot.js derives it.
    assert (
        wallet.wallet_keys(DEV).ss58_address == "5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV"
    )


def test_the_evm_signature_is_the_frozen_personal_sign() -> None:
    keys = wallet.wallet_keys(ABANDON)
    signature = keys.sign_evm(MESSAGE)
    assert signature == FROZEN_EVM_SIGNATURE
    raw = bytes.fromhex(signature[2:])
    recovered = PublicKey.from_signature_and_message(
        raw[:64] + bytes([raw[64] - 27]), wallet.eip191_hash(MESSAGE), hasher=None
    )
    assert recovered.format() == PrivateKey(keys._evm_secret).public_key.format()


def test_the_sr25519_signature_verifies_over_the_raw_message() -> None:
    keys = wallet.wallet_keys(ABANDON)
    signature = bytes.fromhex(keys.sign_sr25519(MESSAGE)[2:])
    public = keys._sr25519[0]
    assert sr25519.verify(signature, MESSAGE.encode(), public)
    assert not sr25519.verify(signature, b"<Bytes>" + MESSAGE.encode() + b"</Bytes>", public)


def test_extra_whitespace_is_normalised_and_bad_phrases_refused() -> None:
    spaced = "  " + ABANDON.replace(" ", "   ") + "\n"
    assert wallet.wallet_keys(spaced).ss58_address == wallet.wallet_keys(ABANDON).ss58_address
    with pytest.raises(ValueError, match="BIP-39"):
        wallet.wallet_keys("abandon " * 12)


def test_the_secrets_stay_out_of_repr() -> None:
    keys = wallet.wallet_keys(ABANDON)
    text = repr(keys)
    assert keys._evm_secret.hex() not in text
    assert keys._sr25519[1].hex() not in text
    assert "5EPCU" in text


def test_ss58_refuses_a_bad_key_or_prefix() -> None:
    with pytest.raises(ValueError, match="32-byte"):
        wallet.ss58_encode(b"short")
    with pytest.raises(ValueError, match="prefix"):
        wallet.ss58_encode(bytes(32), prefix=64)
    assert wallet.ss58_encode(bytes(32), prefix=0).startswith("1")
