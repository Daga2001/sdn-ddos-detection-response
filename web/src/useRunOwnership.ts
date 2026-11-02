import { useEffect, useState } from "react";
import type { Notice, Status } from "./types";
import { activeStates } from "./types";

export function useRunOwnership(
  authenticated: boolean,
  setNotice: (notice: Notice) => void,
) {
  const [ownerId, setOwnerId] = useState<string | null>(null);
  useEffect(() => {
    if (!authenticated) return;
    let owner: string | null = null;
    let leaving = false;
    const url = new URL("/api/ownership", window.location.href);
    url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
    const socket = new WebSocket(url);
    socket.onmessage = (event) => {
      if (leaving) return;
      const message = JSON.parse(event.data) as { owner_id: string };
      owner = message.owner_id;
      setOwnerId(owner);
    };
    socket.onclose = () => {
      if (leaving) return;
      setOwnerId(null);
      setNotice({
        tone: "warning",
        title: "The connection that owns this tab's run was lost.",
        hint: "The lab is stopping any run owned by this tab. Reload before starting another run.",
      });
    };
    const release = () => {
      leaving = true;
      if (owner) navigator.sendBeacon(`/api/owners/${owner}/release`);
      setOwnerId(null);
      socket.close();
    };
    window.addEventListener("pagehide", release);
    return () => {
      window.removeEventListener("pagehide", release);
      release();
    };
  }, [authenticated, setNotice]);
  return ownerId;
}

/** Interpolate a runner clock; event retention and workstation time cannot reset it. */
export function useRunClock(status: Status, connected: boolean) {
  const [elapsed, setElapsed] = useState<number | null>(null);
  useEffect(() => {
    if (!status.run_id || status.elapsed_ms === undefined) {
      setElapsed(null);
      return;
    }
    const sample = status.elapsed_ms;
    const received = performance.now();
    setElapsed(sample);
    if (!connected || !activeStates.includes(status.state)) return;
    const timer = window.setInterval(
      () => setElapsed(sample + performance.now() - received),
      250,
    );
    return () => window.clearInterval(timer);
  }, [status, connected]);
  return elapsed;
}
