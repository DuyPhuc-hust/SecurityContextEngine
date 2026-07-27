/**
 * Rank a task without involving an LLM. Inputs are normalized to non-negative
 * numbers; cost has a floor to avoid division by zero.
 */
export function calculatePriority({ expectedRisk, expectedInformationGain, coverageGap, estimatedCost }) {
  const value = (number) => Math.max(0, Number(number) || 0);
  return (value(expectedRisk) * value(expectedInformationGain) * value(coverageGap)) / Math.max(0.01, value(estimatedCost));
}
