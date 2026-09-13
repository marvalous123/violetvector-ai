import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { BLUE_RULES } from "./blue-detection-service.js";
import { LIVE_ENDPOINT_RULE_SOURCE_REQUIREMENTS } from "./endpoint-fact-correlation-service.js";
import {
  WINDOWS_GENUINE_SOURCE_REFERENCES,
  WINDOWS_GENUINE_SOURCE_VALIDATIONS,
  isGenuineLiveEligible
} from "./windows-genuine-source-validation.js";

describe("Windows genuine-source validation catalogue", () => {
  it("covers every defensive rule exactly once and stays bound to the runtime stream", () => {
    assert.equal(WINDOWS_GENUINE_SOURCE_VALIDATIONS.length, 30);
    assert.deepEqual(
      WINDOWS_GENUINE_SOURCE_VALIDATIONS.map(({ ruleId }) => ruleId).sort(),
      BLUE_RULES.map(({ id }) => id).sort()
    );

    const validationByRule = new Map<string, (typeof WINDOWS_GENUINE_SOURCE_VALIDATIONS)[number]>(
      WINDOWS_GENUINE_SOURCE_VALIDATIONS.map((validation) => [
        validation.ruleId,
        validation
      ])
    );
    assert.equal(validationByRule.size, 30);

    for (const requirement of LIVE_ENDPOINT_RULE_SOURCE_REQUIREMENTS) {
      const validation = validationByRule.get(requirement.ruleId);
      assert.ok(validation, `missing validation for ${requirement.ruleId}`);
      assert.deepEqual(
        {
          provider: validation.provider,
          channel: validation.channel,
          eventFamily: validation.eventFamily
        },
        {
          provider: requirement.provider,
          channel: requirement.channel,
          eventFamily: requirement.eventFamily
        }
      );
      assert.match(validation.limitationCode, /^[A-Z0-9_]{8,120}$/);
      assert.equal(validation.sourceRefs.length > 0, true);
      for (const sourceRef of validation.sourceRefs) {
        assert.match(
          WINDOWS_GENUINE_SOURCE_REFERENCES[sourceRef],
          /^https:\/\/learn\.microsoft\.com\//
        );
      }
    }
  });

  it("freezes the honest pre-machine-validation assessment", () => {
    const counts = Object.fromEntries(
      [
        "correlation-required",
        "enrichment-required",
        "external-source-required",
        "synthetic-only",
        "source-mismatch"
      ].map((assessment) => [
        assessment,
        WINDOWS_GENUINE_SOURCE_VALIDATIONS.filter(
          (validation) => validation.assessment === assessment
        ).length
      ])
    );

    assert.deepEqual(counts, {
      "correlation-required": 18,
      "enrichment-required": 8,
      "external-source-required": 2,
      "synthetic-only": 2,
      "source-mismatch": 0
    });

    assert.deepEqual(
      WINDOWS_GENUINE_SOURCE_VALIDATIONS
        .filter((validation) => !isGenuineLiveEligible(validation.assessment))
        .map((validation) => validation.ruleId)
        .sort(),
      ["BR-CRED-004", "BR-CRED-006", "BR-CRED-007", "BR-CRED-008"]
    );
  });
});
