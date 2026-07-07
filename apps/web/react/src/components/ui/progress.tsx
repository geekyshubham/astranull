import { clamp, cn } from '../../lib/utils';

export type ProgressTone = 'accent' | 'success' | 'warn' | 'danger';
export type ProgressSize = 'sm' | 'default' | 'lg';

type ProgressProps = {
  value: number;
  className?: string;
  tone?: ProgressTone;
  size?: ProgressSize;
  label?: string;
};

export function Progress({ value, className, tone = 'accent', size = 'default', label }: ProgressProps) {
  const clamped = clamp(value);
  const accessibleName = label ? `${label}: ${clamped} percent` : `Progress ${clamped} percent`;

  return (
    <div
      className={cn(
        'progress',
        tone !== 'accent' && `progress-${tone}`,
        size !== 'default' && `progress-${size}`,
        className
      )}
      role="progressbar"
      aria-label={accessibleName}
      aria-valuenow={clamped}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      <span style={{ width: `${clamped}%` }} />
    </div>
  );
}