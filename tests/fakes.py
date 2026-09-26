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
