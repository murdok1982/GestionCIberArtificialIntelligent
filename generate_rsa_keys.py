#!/usr/bin/env python3
"""
Generate the RSA key pair used to sign/verify JWTs (RS256).

Output:
  infrastructure/keys/jwt_private.pem
  infrastructure/keys/jwt_public.pem

Usage:
  python generate_rsa_keys.py            # 2048-bit keys (default)
  python generate_rsa_keys.py --bits 4096
"""
import argparse
import os

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate(bits: int) -> tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate CyberGuard JWT RSA keys")
    parser.add_argument("--bits", type=int, default=2048, choices=[2048, 4096])
    parser.add_argument(
        "--out-dir",
        default=os.path.join(os.path.dirname(__file__), "infrastructure", "keys"),
        help="Directory where the PEM files are written",
    )
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    private_pem, public_pem = generate(args.bits)

    private_path = os.path.join(args.out_dir, "jwt_private.pem")
    public_path = os.path.join(args.out_dir, "jwt_public.pem")

    # Restrict permissions on the private key
    with open(private_path, "wb") as f:
        f.write(private_pem)
    os.chmod(private_path, 0o600)

    with open(public_path, "wb") as f:
        f.write(public_pem)

    print(f"Generated RSA-{args.bits} key pair:")
    print(f"  Private: {private_path}")
    print(f"  Public:  {public_path}")
    print("\nAdd the following to your .env (or use the *_PATH variant):")
    print(f'JWT_PRIVATE_KEY_PATH="{os.path.abspath(private_path)}"')
    print(f'JWT_PUBLIC_KEY_PATH="{os.path.abspath(public_path)}"')


if __name__ == "__main__":
    main()
