export type Level = 'ok' | 'info' | 'warn' | 'bad';
export type Finding = { level: Level; text: string };

/** What a single check reports. `points` out of `max` feeds the overall score. */
export type CheckResult<T = unknown> = {
  id: string;
  title: string;
  status: 'pass' | 'warn' | 'fail' | 'missing' | 'unknown';
  summary: string;
  points: number;
  max: number;
  findings: Finding[];
  record?: string;
  data?: T;
  /** the record is absent but not needed, e.g. SPF and DKIM on a domain that sends no email */
  notRequired?: boolean;
};
