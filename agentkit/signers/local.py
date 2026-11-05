"""Local key-file signer: for tests with throwaway keys only.

The config holds a PATH. The key is read once when the signer is built and
lives only inside an eth_account LocalAccount; repr shows the address only and
the object refuses pickling. Production agents should sign in their own wallet
infrastructure (CDP, Privy, Turnkey, a hardware wallet) or through local OMX.
"""
from __future__ import annotations

from os import PathLike
from pathlib import Path


class LocalKeyFileSigner:
    __slots__ = ("_acct",)

    def __init__(self, key_path: str | PathLike):
        from eth_account import Account
        text = Path(key_path).read_text(encoding="utf-8").strip()
        try:
            self._acct = Account.from_key(text)
        except Exception:
            raise ValueError("key file does not hold a valid hex private key") from None
        finally:
            text = None

    def address(self) -> str:
        return self._acct.address

    def sign_typed_data(self, typed: dict) -> str:
        from eth_account.messages import encode_typed_data
        signed = self._acct.sign_message(encode_typed_data(full_message=typed))
        return "0x" + bytes(signed.signature).hex()

    def __repr__(self) -> str:
        return f"LocalKeyFileSigner(address={self.address()})"

    __str__ = __repr__

    def __reduce__(self):
        raise TypeError("LocalKeyFileSigner cannot be pickled")
