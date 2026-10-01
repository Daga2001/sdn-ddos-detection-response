/** Device and interface icons, drawn inline so the strict CSP needs no exceptions. */

type IconProps = { className?: string };

/** Isometric chassis with the four crossing arrows used for switches. */
function SwitchIcon({ className }: IconProps) {
  return (
    <svg viewBox="0 0 48 48" className={className} aria-hidden="true">
      <path d="M6 18 24 27 42 18 24 9Z" className="icon-top" />
      <path d="M6 18v9.5l18 9.5V27Z" className="icon-left" />
      <path d="M42 18v9.5l-18 9.5V27Z" className="icon-right" />
      <g className="icon-mark">
        <path className="icon-stem" d="M17 14H28M31 22H20" />
        <path
          className="icon-head"
          d="M32 14 27.6 11.5V16.5ZM16 22 20.4 24.5V19.5Z"
        />
      </g>
    </svg>
  );
}

/** Desktop workstation: the default host. */
function HostIcon({ className }: IconProps) {
  return (
    <svg viewBox="0 0 48 48" className={className} aria-hidden="true">
      <rect x="5" y="9" width="38" height="26" rx="2.6" className="icon-body" />
      <rect
        x="8.5"
        y="12.5"
        width="31"
        height="19"
        rx="1.2"
        className="icon-screen"
      />
      <path d="M19.5 35h9l1.4 4h-11.8Z" className="icon-body" />
      <rect
        x="14"
        y="38.6"
        width="20"
        height="3.4"
        rx="1.7"
        className="icon-body"
      />
    </svg>
  );
}

/** Rack server: the host publishing the HTTP service under test. */
function ServerIcon({ className }: IconProps) {
  return (
    <svg viewBox="0 0 48 48" className={className} aria-hidden="true">
      <rect x="11" y="6" width="26" height="36" rx="3" className="icon-body" />
      <g className="icon-screen">
        <rect x="14.5" y="9.5" width="19" height="7.5" rx="1.2" />
        <rect x="14.5" y="20.2" width="19" height="7.5" rx="1.2" />
        <rect x="14.5" y="30.9" width="19" height="7.5" rx="1.2" />
      </g>
      <g className="icon-led">
        <circle cx="18" cy="13.2" r="1.5" />
        <circle cx="18" cy="23.9" r="1.5" />
        <circle cx="18" cy="34.6" r="1.5" />
      </g>
    </svg>
  );
}

/** Workstation with a radiating badge: the bounded traffic source. */
function SourceIcon({ className }: IconProps) {
  return (
    <svg viewBox="0 0 48 48" className={className} aria-hidden="true">
      <rect x="3" y="9" width="34" height="23" rx="2.4" className="icon-body" />
      <rect
        x="6.2"
        y="12.2"
        width="27.6"
        height="16.6"
        rx="1.2"
        className="icon-screen"
      />
      <path d="M16 32h8l1.3 3.6h-10.6Z" className="icon-body" />
      <rect
        x="11"
        y="35.2"
        width="18"
        height="3.2"
        rx="1.6"
        className="icon-body"
      />
      <g className="icon-alert">
        <circle cx="38" cy="36" r="8.4" />
        <path
          d="M34.4 36h7.2M38.6 33 41.8 36l-3.2 3"
          className="icon-alert-mark"
        />
      </g>
    </svg>
  );
}

/** Control-plane appliance: one managed Ryu controller steering every switch. */
function ControllerIcon({ className }: IconProps) {
  return (
    <svg viewBox="0 0 48 48" className={className} aria-hidden="true">
      <rect x="6" y="8" width="36" height="32" rx="4" className="icon-body" />
      <g className="icon-wire">
        <path d="M24 17.5v6.5M24 24 15 30.5M24 24l9 6.5" />
      </g>
      <g className="icon-screen">
        <circle cx="24" cy="15.4" r="3.5" />
        <circle cx="14.4" cy="32.2" r="3.5" />
        <circle cx="33.6" cy="32.2" r="3.5" />
      </g>
    </svg>
  );
}

export function DeviceIcon({
  kind,
  role,
  className,
}: {
  kind: string;
  role?: string;
  className?: string;
}) {
  if (kind === "controller") return <ControllerIcon className={className} />;
  if (kind === "switch") return <SwitchIcon className={className} />;
  if (role === "victim") return <ServerIcon className={className} />;
  if (role === "source") return <SourceIcon className={className} />;
  return <HostIcon className={className} />;
}

export function DownloadIcon() {
  return (
    <svg viewBox="0 0 16 16" className="ui-icon" aria-hidden="true">
      <path
        d="M8 2v8m0 0L4.8 6.8M8 10l3.2-3.2M2.5 12.5h11"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export function CaretIcon() {
  return (
    <svg viewBox="0 0 16 16" className="ui-icon" aria-hidden="true">
      <path
        d="M4 6.5 8 10.5l4-4"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export function PointerIcon() {
  return (
    <svg viewBox="0 0 16 16" className="ui-icon" aria-hidden="true">
      <path
        d="M3 2.2 12.6 7.6 8.4 8.9 6.9 13Z"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export function HandIcon() {
  return (
    <svg viewBox="0 0 16 16" className="ui-icon" aria-hidden="true">
      <path
        d="M5.4 7.6V3.9a1.1 1.1 0 0 1 2.2 0v3.2m0-.3V3.1a1.1 1.1 0 0 1 2.2 0v4m0-.4V4.4a1.1 1.1 0 1 1 2.2 0v4.9c0 2.6-1.6 4.4-4 4.4-2.1 0-3.3-1-4.1-2.6L2.7 9.2a1.1 1.1 0 0 1 1.8-1.2Z"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.3"
        strokeLinejoin="round"
      />
    </svg>
  );
}
