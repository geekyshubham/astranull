import * as React from 'react';
import { cn } from '../../lib/utils';

const CARD_STYLES_ID = 'ui-card-primitive-styles';

const cardPrimitiveStyles = `
[data-ui='card'].card {
  box-shadow: var(--elev-ring);
  color: var(--fg);
}
[data-ui='card'].card-raised {
  background: var(--surface-raised);
  box-shadow: var(--elev-raised);
}
[data-ui='card'] .card-title {
  font-family: var(--font-display);
  font-size: 15px;
  font-weight: 600;
  letter-spacing: -0.01em;
  color: var(--fg);
}
[data-ui='card'] .card-description {
  color: var(--fg-2);
}
[data-ui='card'] .card-footer {
  display: flex;
  align-items: center;
  gap: var(--space-3);
  margin-top: var(--space-4);
  padding-top: var(--space-4);
  border-top: 1px solid var(--border-soft);
}
[data-ui='card'].card-compact .card-footer {
  margin-top: var(--space-3);
  padding-top: var(--space-3);
}
@media (prefers-reduced-motion: reduce) {
  [data-ui='card'].card {
    transition: none;
  }
}
`;

function ensureCardStyles() {
  if (typeof document === 'undefined') return;
  if (document.getElementById(CARD_STYLES_ID)) return;
  const node = document.createElement('style');
  node.id = CARD_STYLES_ID;
  node.textContent = cardPrimitiveStyles;
  document.head.appendChild(node);
}

export type CardProps = React.HTMLAttributes<HTMLDivElement> & {
  density?: 'default' | 'compact';
  /** Slightly elevated surface; uses theme tokens (--surface-raised, --elev-raised). */
  raised?: boolean;
};

export function Card({ className, density = 'default', raised = false, ...props }: CardProps) {
  ensureCardStyles();

  return (
    <div
      data-ui="card"
      className={cn('card', density === 'compact' && 'card-compact', raised && 'card-raised', className)}
      {...props}
    />
  );
}

export function CardHeader({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('card-header', className)} {...props} />;
}

export function CardTitle({ className, ...props }: React.HTMLAttributes<HTMLHeadingElement>) {
  return <h2 className={cn('card-title', className)} {...props} />;
}

export function CardDescription({ className, ...props }: React.HTMLAttributes<HTMLParagraphElement>) {
  return <p className={cn('card-description', className)} {...props} />;
}

export function CardContent({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('card-content', className)} {...props} />;
}

export function CardFooter({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('card-footer', className)} {...props} />;
}