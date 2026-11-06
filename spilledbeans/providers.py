"""Provider metadata: patterns, confidence, and where to revoke/rotate a key.

Every provider entry carries the URL a panicked developer actually needs:
the page where the leaked credential can be revoked or rotated.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

HIGH = "high"
MEDIUM = "medium"
LOW = "low"

CONFIDENCE_ORDER = {LOW: 0, MEDIUM: 1, HIGH: 2}


@dataclass(frozen=True)
class Provider:
    id: str
    name: str
    revoke_url: str
    key_format: str
    rotate_help: str
    patterns: tuple[re.Pattern[str], ...] = field(default_factory=tuple)
    confidence: str = HIGH


def _p(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p) for p in patterns)


# Patterns use a named group "secret" when the secret is only part of the match.
# Boundaries ((?<![A-Za-z0-9_-]) etc.) keep us from matching inside longer tokens.
_B = r"(?<![A-Za-z0-9_\-])"
_E = r"(?![A-Za-z0-9_\-])"

PROVIDERS: dict[str, Provider] = {
    p.id: p
    for p in [
        Provider(
            id="anthropic",
            name="Anthropic",
            revoke_url="https://console.anthropic.com/settings/keys",
            key_format="sk-ant-api03-... (about 108 chars)",
            rotate_help="Delete the key in the Anthropic Console and create a new one.",
            patterns=_p(_B + r"sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,}" + _E),
        ),
        Provider(
            id="openai",
            name="OpenAI",
            revoke_url="https://platform.openai.com/api-keys",
            key_format="sk-proj-... / sk-svcacct-... / legacy sk-... (contains T3BlbkFJ)",
            rotate_help="Revoke the key on the API keys page and create a new one.",
            patterns=_p(
                _B + r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,}" + _E,
                _B + r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}" + _E,
            ),
        ),
        Provider(
            id="aws",
            name="AWS access key",
            revoke_url="https://console.aws.amazon.com/iam/home#/security_credentials",
            key_format="Access key ID AKIA/ASIA + 16 chars; secret key 40 chars",
            rotate_help=(
                "In IAM, deactivate then delete the access key, create a new one, and "
                "check CloudTrail for activity from the leaked key."
            ),
            patterns=_p(
                _B + r"(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}" + _E,
                r"(?i)aws_?secret_?access_?key[\"']?\s*[:=]\s*[\"']?"
                r"(?P<secret>[A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
            ),
        ),
        Provider(
            id="github",
            name="GitHub token",
            revoke_url="https://github.com/settings/tokens",
            key_format="ghp_/gho_/ghu_/ghs_/ghr_ + 36 chars, or github_pat_ + 82 chars",
            rotate_help=(
                "Delete the token under Settings > Developer settings. OAuth/app tokens "
                "(gho_/ghu_/ghs_) are revoked from the app's settings page."
            ),
            patterns=_p(
                _B + r"gh[pousr]_[A-Za-z0-9]{36}" + _E,
                _B + r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}" + _E,
            ),
        ),
        Provider(
            id="huggingface",
            name="Hugging Face",
            revoke_url="https://huggingface.co/settings/tokens",
            key_format="hf_ + 34 chars",
            rotate_help="Invalidate the token on the Access Tokens page and create a new one.",
            patterns=_p(_B + r"hf_[A-Za-z0-9]{34}" + _E),
        ),
        Provider(
            id="stripe",
            name="Stripe",
            revoke_url="https://dashboard.stripe.com/apikeys",
            key_format="sk_live_/rk_live_ (sk_test_/rk_test_ for test mode)",
            rotate_help="Use 'Roll key' on the API keys page. Rolling a live key can break production; plan it.",
            patterns=_p(_B + r"(?:sk|rk)_live_[A-Za-z0-9]{24,}" + _E),
        ),
        Provider(
            id="stripe-test",
            name="Stripe (test mode)",
            revoke_url="https://dashboard.stripe.com/test/apikeys",
            key_format="sk_test_/rk_test_",
            rotate_help="Roll the test key on the test-mode API keys page.",
            patterns=_p(_B + r"(?:sk|rk)_test_[A-Za-z0-9]{24,}" + _E),
            confidence=MEDIUM,
        ),
        Provider(
            id="slack",
            name="Slack",
            revoke_url="https://api.slack.com/apps",
            key_format="xoxb-/xoxp-/xoxa-/xoxr-/xoxs- tokens, or hooks.slack.com webhook URLs",
            rotate_help=(
                "Open the app, then OAuth & Permissions to revoke/reinstall tokens, or "
                "Incoming Webhooks to remove the leaked webhook."
            ),
            patterns=_p(
                _B + r"xox[baprs]-[A-Za-z0-9]{8,}-[A-Za-z0-9\-]{8,}" + _E,
                r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}",
            ),
        ),
        Provider(
            id="google",
            name="Google API key",
            revoke_url="https://console.cloud.google.com/apis/credentials",
            key_format="AIza + 35 chars",
            rotate_help="Delete or regenerate the key under APIs & Services > Credentials, then add API restrictions.",
            patterns=_p(_B + r"AIza[0-9A-Za-z_\-]{35}" + _E),
        ),
    ]
}

GENERIC = Provider(
    id="generic",
    name="Generic secret",
    revoke_url="",
    key_format="High-entropy value assigned to a name like *key*, *secret*, *token*, *password*",
    rotate_help=(
        "Identify which service this credential belongs to and rotate it there. "
        "If it is a password, change it everywhere it was reused."
    ),
    confidence=LOW,
)

ENV_FILE = Provider(
    id="env-file",
    name="Committed .env value",
    revoke_url="",
    key_format="KEY=value line in a committed .env file",
    rotate_help="Rotate this value with whichever service issued it.",
    confidence=MEDIUM,
)

ALL_PROVIDERS: dict[str, Provider] = {**PROVIDERS, GENERIC.id: GENERIC, ENV_FILE.id: ENV_FILE}

GITHUB_SENSITIVE_DATA_DOCS = (
    "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/"
    "removing-sensitive-data-from-a-repository"
)


def get(provider_id: str) -> Provider:
    return ALL_PROVIDERS.get(provider_id, GENERIC)
