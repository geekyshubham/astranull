import { useEffect, useId, useRef, useState } from 'react';
import { ChevronDown, X } from 'lucide-react';
import type { DataItem } from '../../lib/types';

function getString(item: DataItem, keys: string[], fallback = '') {
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function getNumber(item: DataItem, keys: string[], fallback = 0) {
  for (const key of keys) {
    const value = item[key];
    if (typeof value === 'number' && Number.isFinite(value)) return value;
  }
  return fallback;
}

export type TargetGroupPickerProps = {
  groups: DataItem[];
  selectedIds: string[];
  onChange: (ids: string[]) => void;
  disabled?: boolean;
  label?: string;
};

export function TargetGroupPicker({
  groups,
  selectedIds,
  onChange,
  disabled = false,
  label = 'Target groups'
}: TargetGroupPickerProps) {
  const menuId = useId();
  const rootRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    function onPointerDown(event: MouseEvent) {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    }
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') setOpen(false);
    }
    document.addEventListener('mousedown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('mousedown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, []);

  function toggleGroup(id: string) {
    if (selectedIds.includes(id)) {
      onChange(selectedIds.filter((value) => value !== id));
      return;
    }
    onChange([...selectedIds, id]);
  }

  const selectedGroups = groups.filter((group) => selectedIds.includes(getString(group, ['id'])));

  return (
    <div className="tg-picker-field">
      <span className="field-label">{label}</span>
      <div className="tg-picker" data-tg-picker ref={rootRef}>
        <button
          type="button"
          className="tg-picker-trigger input"
          aria-haspopup="listbox"
          aria-expanded={open}
          aria-controls={menuId}
          disabled={disabled}
          onClick={() => setOpen((value) => !value)}
        >
          <span className="tg-picker-values">
            {selectedGroups.length === 0 ? (
              <span className="tg-picker-placeholder">Select one or more target groups…</span>
            ) : (
              selectedGroups.map((group) => {
                const id = getString(group, ['id']);
                const name = getString(group, ['name', 'id']);
                return (
                  <span key={id} className="tg-chip">
                    {name}
                    <span
                      role="button"
                      tabIndex={0}
                      className="tg-chip-remove"
                      aria-label={`Remove ${name}`}
                      onClick={(event) => {
                        event.stopPropagation();
                        onChange(selectedIds.filter((value) => value !== id));
                      }}
                      onKeyDown={(event) => {
                        if (event.key === 'Enter' || event.key === ' ') {
                          event.preventDefault();
                          event.stopPropagation();
                          onChange(selectedIds.filter((value) => value !== id));
                        }
                      }}
                    >
                      <X size={12} aria-hidden="true" />
                    </span>
                  </span>
                );
              })
            )}
          </span>
          <ChevronDown className="tg-picker-chevron" size={12} aria-hidden="true" />
        </button>
        <div className="tg-picker-menu" id={menuId} role="listbox" aria-multiselectable="true" hidden={!open}>
          {groups.map((group) => {
            const id = getString(group, ['id']);
            const name = getString(group, ['name', 'id']);
            const env = getString(group, ['environment_id'], '—');
            const criticality = getString(group, ['criticality'], '—');
            const targetCount = getNumber(group, ['target_count', 'targets_count']);
            const checked = selectedIds.includes(id);
            return (
              <label key={id} className="tg-picker-row" role="option" aria-selected={checked}>
                <input
                  type="checkbox"
                  checked={checked}
                  onChange={() => toggleGroup(id)}
                  disabled={disabled}
                />
                <span className="tg-check-box" aria-hidden="true" />
                <span className="tg-name">{name}</span>
                <span className="tg-meta">{env} · {criticality} · {targetCount} targets</span>
              </label>
            );
          })}
        </div>
      </div>
    </div>
  );
}