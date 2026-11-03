"""
Password utilities: cryptographically secure generator and strength analyzer.
"""

import math
import re
import secrets
import string


# ---------------------------------------------------------------------------
# Password Generator
# ---------------------------------------------------------------------------

def generate_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> str:
    """
    Generate a cryptographically secure random password.

    Args:
        length: Desired password length (min 4, max 128).
        use_upper: Include uppercase letters.
        use_lower: Include lowercase letters.
        use_digits: Include digits.
        use_symbols: Include symbols.
        exclude_ambiguous: Remove visually ambiguous characters (0O, 1lI).

    Returns:
        A random password string.
    """
    length = max(4, min(128, length))

    charset = ""
    required: list[str] = []

    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"

    if exclude_ambiguous:
        upper = upper.replace("O", "").replace("I", "")
        lower = lower.replace("l", "")
        digits = digits.replace("0", "").replace("1", "")

    if use_upper:
        charset += upper
        required.append(secrets.choice(upper))
    if use_lower:
        charset += lower
        required.append(secrets.choice(lower))
    if use_digits:
        charset += digits
        required.append(secrets.choice(digits))
    if use_symbols:
        charset += symbols
        required.append(secrets.choice(symbols))

    if not charset:
        charset = string.ascii_letters + string.digits
        required.append(secrets.choice(string.ascii_lowercase))

    # Fill remaining length
    remaining = length - len(required)
    password_chars = required + [secrets.choice(charset) for _ in range(remaining)]

    # Shuffle to avoid predictable positions for required chars
    # Use Fisher-Yates with secrets for uniform shuffle
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars)


# ---------------------------------------------------------------------------
# Strength Analyzer
# ---------------------------------------------------------------------------

COMMON_PATTERNS = [
    r"^123456",
    r"password",
    r"qwerty",
    r"abc123",
    r"letmein",
    r"admin",
    r"welcome",
    r"monkey",
    r"master",
    r"dragon",
    r"login",
    r"^111111",
    r"^000000",
    r"passw0rd",
    r"shadow",
    r"sunshine",
    r"trustno1",
    r"iloveyou",
]


def analyze_strength(password: str) -> dict:
    """
    Analyze password strength and return a detailed report.

    Returns:
        {
            "score": int 0-100,
            "rating": "Very Weak" | "Weak" | "Fair" | "Strong" | "Very Strong",
            "entropy": float,
            "feedback": [str],
            "checks": {
                "length": bool,
                "uppercase": bool,
                "lowercase": bool,
                "digits": bool,
                "symbols": bool,
                "no_common": bool,
            }
        }
    """
    feedback = []
    score = 0

    # --- Character class checks ---
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_symbol = bool(re.search(r"[^A-Za-z0-9]", password))
    length = len(password)

    # --- Length scoring (max 35) ---
    if length >= 16:
        score += 35
    elif length >= 12:
        score += 25
    elif length >= 8:
        score += 15
    elif length >= 6:
        score += 8
    else:
        score += 3
        feedback.append("Use at least 8 characters")

    if length < 8:
        feedback.append("Password is too short")

    # --- Char variety scoring (max 40) ---
    variety_count = sum([has_upper, has_lower, has_digit, has_symbol])
    score += variety_count * 10

    if not has_upper:
        feedback.append("Add uppercase letters")
    if not has_lower:
        feedback.append("Add lowercase letters")
    if not has_digit:
        feedback.append("Add numbers")
    if not has_symbol:
        feedback.append("Add special characters (!@#$%…)")

    # --- Entropy bonus (max 15) ---
    charset_size = 0
    if has_upper:
        charset_size += 26
    if has_lower:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_symbol:
        charset_size += 32

    entropy = length * math.log2(charset_size) if charset_size > 0 else 0

    if entropy >= 80:
        score += 15
    elif entropy >= 60:
        score += 10
    elif entropy >= 40:
        score += 5

    # --- Common pattern penalty (max -20) ---
    has_common = False
    for pattern in COMMON_PATTERNS:
        if re.search(pattern, password, re.IGNORECASE):
            has_common = True
            score -= 20
            feedback.append("Avoid common passwords and patterns")
            break

    # --- Repeated characters penalty ---
    if re.search(r"(.)\1{2,}", password):
        score -= 10
        feedback.append("Avoid repeating characters (aaa, 111)")

    # --- Sequential characters penalty ---
    if re.search(r"(012|123|234|345|456|567|678|789|abc|bcd|cde|def)", password, re.IGNORECASE):
        score -= 5
        feedback.append("Avoid sequential characters")

    # Clamp
    score = max(0, min(100, score))

    # Rating
    if score >= 80:
        rating = "Very Strong"
    elif score >= 60:
        rating = "Strong"
    elif score >= 40:
        rating = "Fair"
    elif score >= 20:
        rating = "Weak"
    else:
        rating = "Very Weak"

    if not feedback:
        feedback.append("Excellent password!")

    return {
        "score": score,
        "rating": rating,
        "entropy": round(entropy, 1),
        "feedback": feedback,
        "checks": {
            "length": length >= 8,
            "uppercase": has_upper,
            "lowercase": has_lower,
            "digits": has_digit,
            "symbols": has_symbol,
            "no_common": not has_common,
        },
    }
