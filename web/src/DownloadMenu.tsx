/** One download button, with the file formats folded into its dropdown. */

import { useEffect, useRef, useState } from "react";
import { CaretIcon, DownloadIcon } from "./Icons";

export type DownloadChoice = {
  label: string;
  note: string;
  run: () => void;
};

export function DownloadMenu({
  choices,
  disabled,
}: {
  choices: DownloadChoice[];
  disabled: boolean;
}) {
  const [open, setOpen] = useState(false);
  const container = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    function dismiss(event: MouseEvent) {
      if (!container.current?.contains(event.target as Node)) setOpen(false);
    }
    function escape(event: KeyboardEvent) {
      if (event.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", dismiss);
    document.addEventListener("keydown", escape);
    return () => {
      document.removeEventListener("mousedown", dismiss);
      document.removeEventListener("keydown", escape);
    };
  }, [open]);
  useEffect(() => {
    if (disabled) setOpen(false);
  }, [disabled]);
  return (
    <div className="split-button" ref={container}>
      <button
        disabled={disabled}
        className="split-main"
        onClick={() => {
          setOpen(false);
          choices[0].run();
        }}
      >
        <DownloadIcon />
        Download
      </button>
      <button
        disabled={disabled}
        className="split-toggle"
        aria-label="Choose a download format"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
      >
        <CaretIcon />
      </button>
      {open && (
        <div className="split-menu" role="menu">
          {choices.map((choice) => (
            <button
              key={choice.label}
              role="menuitem"
              onClick={() => {
                setOpen(false);
                choice.run();
              }}
            >
              <strong>{choice.label}</strong>
              <small>{choice.note}</small>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
