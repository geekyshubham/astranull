import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatNumber(value: unknown, fallback = '0') {
  if (typeof value !== 'number' || !Number.isFinite(value)) return fallback;
  return new Intl.NumberFormat('en-US').format(value);
}

export function formatDate(value: unknown) {
  if (!value) return 'Not recorded';
  const date = new Date(String(value));
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}

export function asArray<T = Record<string, unknown>>(value: unknown): T[] {
  if (Array.isArray(value)) return value as T[];
  if (value && typeof value === 'object' && Array.isArray((value as { items?: unknown }).items)) {
    return (value as { items: T[] }).items;
  }
  return [];
}

export function scoreTone(score: number) {
  if (score >= 80) return 'success';
  if (score >= 55) return 'warn';
  return 'danger';
}

export function clamp(value: number, min = 0, max = 100) {
  return Math.min(max, Math.max(min, value));
}

const SEVERITY_LABELS: Record<string, string> = {
  s1: 'Severity 1 · Critical',
  s2: 'Severity 2 · High',
  s3: 'Severity 3 · Medium',
  s4: 'Severity 4 · Low',
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info'
};

export function formatSeverityLabel(severity: string, fallback = 'Unknown') {
  const key = severity.trim().toLowerCase();
  if (!key) return fallback;
  return SEVERITY_LABELS[key] ?? severity.replace(/_/g, ' ');
}

export function formatAuditAction(action: string, fallback = 'Unknown action') {
  const key = action.trim();
  if (!key) return fallback;
  return key.replace(/\./g, ' · ').replace(/_/g, ' ');
}

export function formatResourceTypeLabel(resourceType: string, fallback = 'Record') {
  const key = resourceType.trim().toLowerCase();
  if (!key) return fallback;
  return key.replace(/_/g, ' ');
}

const EXPECTED_BEHAVIOR_LABELS: Record<string, string> = {
  must_block_before_origin: 'Must be blocked before origin',
  must_allow_baseline_health: 'Must allow baseline health',
  must_challenge_or_rate_limit: 'Must challenge or rate-limit',
  must_not_expose_direct_ip: 'Must not expose direct IP'
};

export function formatExpectedBehavior(value: string) {
  return EXPECTED_BEHAVIOR_LABELS[value] ?? value.replace(/_/g, ' ');
}
