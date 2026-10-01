import { useEffect, useState } from "react";
import type { Topology } from "./types";
import { hostSwitch } from "./types";

/**
 * A modal host chooser: a paginated table of every host with its address and the
 * switch it hangs off, and a checkbox per row. Hosts already taken by the other
 * role are shown but locked, so a host can never be an attacker and a victim at
 * once. Replaces the cramped inline checklist that did not scale past a handful
 * of hosts.
 */
export function HostPicker({
  title,
  open,
  topology,
  selected,
  blocked,
  blockedLabel,
  onToggle,
  onClose,
}: {
  title: string;
  open: boolean;
  topology: Topology | null;
  selected: string[];
  blocked: string[];
  blockedLabel: string;
  onToggle: (name: string) => void;
  onClose: () => void;
}) {
  const [page, setPage] = useState(0);
  const [perPage, setPerPage] = useState(5);
  const hosts = topology?.hosts ?? [];
  const pages = Math.max(1, Math.ceil(hosts.length / perPage));
  const current = Math.min(page, pages - 1);
  const rows = hosts.slice(current * perPage, current * perPage + perPage);

  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);
  useEffect(() => {
    if (open) setPage(0);
  }, [open]);

  if (!open) return null;
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onClick={(event) => event.stopPropagation()}
      >
        <div className="modal-head">
          <h3>{title}</h3>
          <span className="modal-count">{selected.length} selected</span>
          <button className="modal-close" aria-label="Close" onClick={onClose}>
            ×
          </button>
        </div>
        <div className="data-table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Host name</th>
                <th>IP address</th>
                <th>Switch parent</th>
                <th className="col-check">Select</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((host) => {
                const isBlocked = blocked.includes(host.name);
                const isOn = selected.includes(host.name);
                return (
                  <tr
                    key={host.name}
                    className={`${isOn ? "on" : ""} ${isBlocked ? "blocked" : ""}`}
                  >
                    <td className="mono">{host.name}</td>
                    <td className="mono">{host.ip}</td>
                    <td className="mono">{hostSwitch(topology, host.name)}</td>
                    <td className="col-check">
                      {isBlocked ? (
                        <span className="blocked-note">{blockedLabel}</span>
                      ) : (
                        <input
                          type="checkbox"
                          checked={isOn}
                          aria-label={`Select ${host.name}`}
                          onChange={() => onToggle(host.name)}
                        />
                      )}
                    </td>
                  </tr>
                );
              })}
              {!rows.length && (
                <tr>
                  <td colSpan={4} className="empty-cell">
                    No hosts to choose. Load a topology first.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <div className="modal-foot">
          <label className="per-page">
            Rows
            <select
              value={perPage}
              onChange={(event) => {
                setPerPage(Number(event.target.value));
                setPage(0);
              }}
            >
              <option value={5}>5</option>
              <option value={10}>10</option>
            </select>
          </label>
          <div className="pager">
            <button
              disabled={current === 0}
              onClick={() => setPage(current - 1)}
            >
              ← Prev
            </button>
            <span>
              Page {current + 1} of {pages}
            </span>
            <button
              disabled={current >= pages - 1}
              onClick={() => setPage(current + 1)}
            >
              Next →
            </button>
          </div>
          <button className="primary" onClick={onClose}>
            Done
          </button>
        </div>
      </div>
    </div>
  );
}
