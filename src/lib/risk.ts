export type Risk = 'low' | 'medium' | 'high';

/** How each risk level is worded on screen and in reports. */
export const RISK_LABEL: Record<Risk, string> = { low: 'Low', medium: 'Moderate', high: 'High' };
