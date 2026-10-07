import { describe, expect, it } from "vitest";
import { ago, confidenceTone, dur, ms, riskTone, title, toneOf } from "./format";

describe("toneOf", () => {
  it("maps statuses to the semantic colour vocabulary", () => {
    expect(toneOf("running")).toBe("ok");
    expect(toneOf("COMMITTED")).toBe("ok");
    expect(toneOf("P1")).toBe("crit");
    expect(toneOf("ROLLED_BACK")).toBe("high");
    expect(toneOf("AWAITING_APPROVAL")).toBe("warn");
    expect(toneOf("AUTOMATE")).toBe("auto");
    expect(toneOf("DRY_RUN")).toBe("unk");
    expect(toneOf("approval required")).toBe("warn");
  });
  it("falls back to neutral, and to critical for failures", () => {
    expect(toneOf(undefined)).toBe("neutral");
    expect(toneOf("something new")).toBe("neutral");
    expect(toneOf("VERIFICATION_FAILED")).toBe("crit");
  });
});

describe("risk and confidence thresholds", () => {
  it("uses the backend risk levels (80/60/30)", () => {
    expect(riskTone(91)).toBe("crit");
    expect(riskTone(60)).toBe("high");
    expect(riskTone(30)).toBe("warn");
    expect(riskTone(12)).toBe("ok");
  });
  it("maps identity confidence bands", () => {
    expect(confidenceTone(100)).toBe("ok");
    expect(confidenceTone(65)).toBe("warn");
    expect(confidenceTone(5)).toBe("crit");
  });
});

describe("formatting", () => {
  it("formats durations", () => {
    expect(dur(2)).toBe("2.0 s");
    expect(dur(95)).toBe("1m 35s");
    expect(dur(null)).toBe("-");
    expect(ms(450)).toBe("450 ms");
    expect(ms(1300)).toBe("1.3 s");
  });
  it("formats relative time and titles", () => {
    expect(ago(new Date(Date.now() - 5 * 60_000).toISOString())).toBe("5m ago");
    expect(title("APPROVAL_REQUIRED")).toBe("Approval required");
  });
});
