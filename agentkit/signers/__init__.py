"""Signer adapters (D3). Every signer turns EIP-712 typed data into a 65-byte signature.

None of the hosted-wallet adapters has been executed against a real account:
each needs the user's own provider account and credentials, which this repo
never holds. Credentials enter only through caller-supplied header callables.
"""
from .base import HttpTransport, Signer, SignerError, signature_hex
from .cdp import CdpServerWalletSigner
from .local import LocalKeyFileSigner
from .privy import PrivySigner
from .turnkey import TurnkeySigner

__all__ = ["Signer", "SignerError", "HttpTransport", "signature_hex", "LocalKeyFileSigner",
           "CdpServerWalletSigner", "PrivySigner", "TurnkeySigner"]
