from __future__ import annotations

import unittest

from defensive_ai_gateway.action_plan import normalize_action_plan
from defensive_ai_gateway.models import RecommendedAction


class ActionPlanNormalizationTest(unittest.TestCase):
    def test_numbering_is_removed_and_security_operations_order_is_stable(self):
        actions = [
            RecommendedAction("3) 修复受影响组件并升级版本", "observe", "fix"),
            RecommendedAction("1. 核实攻击源、目标与影响范围", "observe", "verify"),
            RecommendedAction("- 持续监控同源事件 30 分钟", "observe", "monitor"),
            RecommendedAction("2、隔离受影响主机", "approve_required", "contain"),
            RecommendedAction("（4）恢复业务并验证健康状态", "approve_required", "recover"),
        ]

        normalized = normalize_action_plan(actions)

        self.assertEqual(
            [item.stage for item in normalized],
            ["verify", "contain", "eradicate", "recover", "monitor"],
        )
        self.assertEqual(
            [item.action for item in normalized],
            [
                "核实攻击源、目标与影响范围",
                "隔离受影响主机",
                "修复受影响组件并升级版本",
                "恢复业务并验证健康状态",
                "持续监控同源事件 30 分钟",
            ],
        )

    def test_equivalent_numbered_actions_are_deduplicated(self):
        actions = [
            RecommendedAction("1. 封禁恶意来源 IP", "approve_required", "first"),
            RecommendedAction("2、封禁恶意来源 IP。", "approve_required", "duplicate"),
        ]

        normalized = normalize_action_plan(actions)

        self.assertEqual(len(normalized), 1)
        self.assertEqual(normalized[0].action, "封禁恶意来源 IP")
        self.assertEqual(normalized[0].stage, "contain")


if __name__ == "__main__":
    unittest.main()
