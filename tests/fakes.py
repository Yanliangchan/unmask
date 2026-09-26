from __future__ import annotations

from app.adapters.base import AdapterError, EntityCandidate, RawResult, SignatureMismatch, ToolAdapter


class FakeUsernameAdapter(ToolAdapter):
    name = "fake_ok"
    label = "Fake OK"
    input_types = ["username"]
    health_check_target = "known"

    async def run(self, target_value, context_tags):
        if target_value == "blocked":
            raise SignatureMismatch("bot-detection page instead of results")
        return [RawResult(self.name, target_value, {"sites": ["alpha", "beta"]})]

    def parse(self, raw):
        return [
            EntityCandidate(
                type="account",
                value=f"https://{site}.example/{raw.target_value}",
                attributes={"site": site, "url": f"https://{site}.example/{raw.target_value}"},
                source_reliability="C",
                confidence=0.4,
                relation_type="has_account",
                relation_explanation=f"registered on {site}",
            )
            for site in raw.payload["sites"]
        ]


class FakeFailingAdapter(ToolAdapter):
    name = "fake_fail"
    label = "Fake Fail"
    input_types = ["username"]

    async def run(self, target_value, context_tags):
        raise AdapterError("upstream returned HTTP 503")

    def parse(self, raw):
        return []


class FakeEmailAdapter(ToolAdapter):
    """Registration checker: only addresses at acme-corp.example are 'registered'."""

    name = "fake_email"
    label = "Fake Email"
    input_types = ["email"]

    async def run(self, target_value, context_tags):
        return [RawResult(self.name, target_value, {"email": target_value})]

    def parse(self, raw):
        email = raw.payload["email"]
        if not email.endswith("@acme-corp.example"):
            return []
        return [
            EntityCandidate(
                type="registration",
                value=f"{email} @ {site}",
                attributes={"site": site, "email": email},
                source_reliability="B",
                confidence=0.7,
                relation_type="registered_on",
                relation_explanation=f"registered on {site}",
            )
            for site in ("spotify.com", "github.com")
        ]


class FakeDomainAdapter(ToolAdapter):
    name = "fake_domain"
    label = "Fake Domain"
    input_types = ["domain"]

    async def run(self, target_value, context_tags):
        return [RawResult(self.name, target_value, {"domain": target_value})]

    def parse(self, raw):
        d = raw.payload["domain"]
        return [
            EntityCandidate(type="hostname", value=f"{h}.{d}", source_reliability="B", confidence=0.6,
                            relation_type="subdomain", relation_explanation="found by fake_domain")
            for h in ("www", "mail")
        ]  # fmt: skip
