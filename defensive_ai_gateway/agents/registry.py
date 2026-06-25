from __future__ import annotations

from ..llm import LLMClient
from ..policy import PolicyEngine
from .base import SecurityAgent
from .hips import HipsAgent
from .ndr import NdrAgent
from .rasp import RaspAgent
from .siem import SiemAgent
from .waf import WafAgent


AGENT_TYPES = {
    "hips": HipsAgent,
    "rasp": RaspAgent,
    "ndr": NdrAgent,
    "waf": WafAgent,
    "siem": SiemAgent,
}


def build_agent(product: str, llm: LLMClient, policy: PolicyEngine) -> SecurityAgent:
    agent_type = AGENT_TYPES.get(product.lower(), SiemAgent)
    return agent_type(llm, policy)

