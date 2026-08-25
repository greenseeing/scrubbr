"""Synthetic, secret-shaped strings for the detection suite.

Every value here is a hand-typed keyboard pattern, not a real credential: the
shapes are right (prefix, length, charset) so the rules fire, but no value
authenticates anything. Keep them synthetic even though tests/ is gitleaks-
allowlisted -- a real secret pasted here would go unflagged.

Each value is assembled from fragments rather than written as one literal. That
keeps a contiguous credential-shaped string out of the source text, so GitHub's
push-protection secret scanner (which does not honour .gitleaks.toml) does not
false-positive on these fakes. The assembled runtime values are exactly the tokens
the rules are written to catch.
"""

# ghp_ + 36 base62 (40 chars total). SCRUB tier: distinctive prefix + fixed length.
GITHUB_PAT = "ghp" + "_A1B2C3D4E5F6G7H8J9K0L1M2N3P4Q5R6S7T8"
GITHUB_OAUTH = "gho" + "_Z9Y8X7W6V5U4T3S2R1Q0P9N8M7L6K5J4H3G2"

# SK + 32 hex. WARN tier: 32-hex collides with MD5/IDs, too collision-prone to scrub.
TWILIO_SK = "SK" + "0123456789abcdef" * 2

# pk_live_ publishable key -- a PUBLIC identifier, deliberately left unchanged.
STRIPE_PK = "pk" + "_live_51ABCdefGHIjklMNOpqrSTU0vw"

# A generic high-entropy token behind no distinctive prefix: the REPORT-ONLY net's job.
GENERIC_HIGH_ENTROPY = "kJH8s2Vx9pQ7wLm3tR5uYq2Zx8Nw4Kd"
