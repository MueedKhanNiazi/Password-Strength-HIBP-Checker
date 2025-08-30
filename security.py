
import hashlib
import requests
from zxcvbn import zxcvbn


def analyze_password(password: str) -> dict:
    """Analyze password strength using zxcvbn."""
    result = zxcvbn(password)

    score = result["score"]  # 0–4
    crack_time = result["crack_times_display"]["offline_slow_hashing_1e4_per_second"]
    suggestions = result["feedback"]["suggestions"]

    return {
        "score": score,
        "crack_time": crack_time,
        "suggestions": suggestions
    }


def check_pwned_password(password: str) -> str:
    """Check with Have I Been Pwned API if the password has been breached."""
    try:
        # Create SHA-1 hash of password
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]

        # send HIBP only first 5 characters of the pass
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            return "Error connecting to breach database."

        # Look for suffix in response
        hashes = (line.split(":") for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return f"Found {count} times in data breaches!"

        return "Never pwned."
    except requests.exceptions.RequestException:
        return "No internet – breach check skipped."
