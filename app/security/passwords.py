try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError

    _ph = PasswordHasher()

    def hash_password(password: str) -> str:
        return _ph.hash(password)

    def verify_password(password: str, pw_hash: str) -> bool:
        try:
            return _ph.verify(pw_hash, password)
        except VerifyMismatchError:
            return False
except ImportError:
    import bcrypt

    def hash_password(password: str) -> str:
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    def verify_password(password: str, pw_hash: str) -> bool:
        try:
            return bcrypt.checkpw(password.encode("utf-8"), pw_hash.encode("utf-8"))
        except ValueError:
            return False
