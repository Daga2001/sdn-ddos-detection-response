/**
 * Labelled inputs whose meaning is explained on hover, focus, or tap.
 *
 * The explain button stays outside the <label> element: an interactive
 * descendant there would strip the control of its accessible name.
 */

import { useId, useState } from "react";
import type { ReactNode } from "react";

export function Hint({ text }: { text: string }) {
  const [pinned, setPinned] = useState(false);
  const [hovered, setHovered] = useState(false);
  const id = useId();
  const open = pinned || hovered;
  return (
    <span className="hint">
      <button
        type="button"
        className="hint-button"
        aria-label={`What this means: ${text}`}
        aria-expanded={open}
        aria-describedby={open ? id : undefined}
        onClick={(event) => {
          event.preventDefault();
          setPinned(!pinned);
        }}
        onPointerEnter={() => setHovered(true)}
        onPointerLeave={() => setHovered(false)}
        onFocus={() => setHovered(true)}
        onBlur={() => {
          setHovered(false);
          setPinned(false);
        }}
      >
        i
      </button>
      {open && (
        <span role="tooltip" id={id} className="hint-bubble">
          {text}
        </span>
      )}
    </span>
  );
}

export function Field({
  label,
  hint,
  children,
  className,
}: {
  label: string;
  hint: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={`field ${className ?? ""}`}>
      <label>
        <span className="field-label">{label}</span>
        {children}
      </label>
      <Hint text={hint} />
    </div>
  );
}

export function CheckField({
  label,
  hint,
  checked,
  onChange,
  className,
  disabled,
}: {
  label: string;
  hint: string;
  checked: boolean;
  onChange: (value: boolean) => void;
  className?: string;
  disabled?: boolean;
}) {
  return (
    <div className={`field check-field ${className ?? ""}`}>
      <label className="checkbox">
        <input
          type="checkbox"
          checked={checked}
          disabled={disabled}
          onChange={(event) => onChange(event.target.checked)}
        />
        <span>{label}</span>
      </label>
      <Hint text={hint} />
    </div>
  );
}
