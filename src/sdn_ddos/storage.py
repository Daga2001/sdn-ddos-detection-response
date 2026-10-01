"""PostgreSQL persistence for network metrics and experiment events."""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, List, Protocol
from uuid import UUID

from sdn_ddos.config import DatabaseSettings


class MetricsStore(Protocol):
    """Persistence contract used by controller and experiment components."""

    def add_flow_rows(self, rows: List[Dict[str, Any]]) -> None: ...

    def add_port_rows(self, rows: List[Dict[str, Any]]) -> None: ...

    def add_controller_row(self, row: Dict[str, Any]) -> None: ...

    def record_detection(self, row: Dict[str, Any]) -> None: ...

    def record_mitigation(self, row: Dict[str, Any]) -> None: ...

    def record_attack_window(
        self, start: datetime, end: datetime, attack_type: str, target_ip: str
    ) -> None: ...

    def flush(self, force: bool = False) -> None: ...

    def close(self) -> None: ...


class NullMetricsStore:
    """No-op store used when database collection is intentionally disabled."""

    def add_flow_rows(self, rows: List[Dict[str, Any]]) -> None:
        return None

    def add_port_rows(self, rows: List[Dict[str, Any]]) -> None:
        return None

    def add_controller_row(self, row: Dict[str, Any]) -> None:
        return None

    def record_detection(self, row: Dict[str, Any]) -> None:
        return None

    def record_mitigation(self, row: Dict[str, Any]) -> None:
        return None

    def record_attack_window(
        self, start: datetime, end: datetime, attack_type: str, target_ip: str
    ) -> None:
        return None

    def flush(self, force: bool = False) -> None:
        return None

    def close(self) -> None:
        return None


class PostgreSQLMetricsStore:
    """Buffered metrics store using one controller-owned PostgreSQL connection."""

    def __init__(self, settings: DatabaseSettings, flush_rows: int = 100) -> None:
        import psycopg2

        raw_run_id = os.environ.get("SDN_RUN_ID", "")
        self._run_id = str(UUID(raw_run_id)) if raw_run_id else None
        self._connection = psycopg2.connect(
            host=settings.host,
            port=settings.port,
            dbname=settings.database,
            user=settings.user,
            password=settings.password,
            connect_timeout=settings.connect_timeout_seconds,
            application_name="sdn-ddos-research",
        )
        self._connection.autocommit = False
        self._flush_rows = flush_rows
        self._flow_rows: List[Dict[str, Any]] = []
        self._port_rows: List[Dict[str, Any]] = []
        self._controller_rows: List[Dict[str, Any]] = []

    def add_flow_rows(self, rows: List[Dict[str, Any]]) -> None:
        self._flow_rows.extend(rows)
        self.flush()

    def add_port_rows(self, rows: List[Dict[str, Any]]) -> None:
        self._port_rows.extend(rows)
        self.flush()

    def add_controller_row(self, row: Dict[str, Any]) -> None:
        self._controller_rows.append(row)
        self.flush()

    def flush(self, force: bool = False) -> None:
        if (
            not force
            and max(
                len(self._flow_rows),
                len(self._port_rows),
                len(self._controller_rows),
            )
            < self._flush_rows
        ):
            return

        flow_count = len(self._flow_rows)
        port_count = len(self._port_rows)
        controller_count = len(self._controller_rows)
        if flow_count + port_count + controller_count == 0:
            return
        cursor = self._connection.cursor()
        try:
            if flow_count:
                self._execute_batch(
                    cursor,
                    """
                    INSERT INTO flow_stats (
                        ts, dpid, table_id, priority, cookie,
                        eth_src, eth_dst, ipv4_src, ipv4_dst,
                        ip_proto, l4_src_port, l4_dst_port,
                        packet_count, byte_count, duration_sec, duration_nsec,
                        pktrate, byterate, label, prob_ddos
                    ) VALUES (
                        %(ts)s, %(dpid)s, %(table_id)s, %(priority)s, %(cookie)s,
                        %(eth_src)s, %(eth_dst)s, %(ipv4_src)s, %(ipv4_dst)s,
                        %(ip_proto)s, %(l4_src_port)s, %(l4_dst_port)s,
                        %(packet_count)s, %(byte_count)s, %(duration_sec)s,
                        %(duration_nsec)s, %(pktrate)s, %(byterate)s,
                        %(label)s, %(prob_ddos)s
                    )
                    """,
                    self._flow_rows[:flow_count],
                    page_size=500,
                )
            if port_count:
                self._execute_batch(
                    cursor,
                    """
                    INSERT INTO port_stats (
                        ts, dpid, port_no, rx_packets, tx_packets,
                        rx_bytes, tx_bytes, rx_dropped, tx_dropped,
                        rx_errors, tx_errors, rx_byterate, tx_byterate
                    ) VALUES (
                        %(ts)s, %(dpid)s, %(port_no)s, %(rx_packets)s,
                        %(tx_packets)s, %(rx_bytes)s, %(tx_bytes)s,
                        %(rx_dropped)s, %(tx_dropped)s, %(rx_errors)s,
                        %(tx_errors)s, %(rx_byterate)s, %(tx_byterate)s
                    )
                    """,
                    self._port_rows[:port_count],
                    page_size=500,
                )
            if controller_count:
                self._execute_batch(
                    cursor,
                    """
                    INSERT INTO controller_stats (ts, cpu_percent, rss_bytes)
                    VALUES (%(ts)s, %(cpu_percent)s, %(rss_bytes)s)
                    """,
                    self._controller_rows[:controller_count],
                    page_size=500,
                )
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise
        finally:
            cursor.close()

        # Remove rows only after all batches commit so a partial failure does
        # not silently discard research data.
        del self._flow_rows[:flow_count]
        del self._port_rows[:port_count]
        del self._controller_rows[:controller_count]

    def _execute_event(self, query: str, values: Dict[str, Any]) -> None:
        query, tagged = self._tag_run(query, [values])
        cursor = self._connection.cursor()
        try:
            cursor.execute(query, tagged[0])
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise
        finally:
            cursor.close()

    def _tag_run(
        self, query: str, rows: List[Dict[str, Any]]
    ) -> tuple[str, List[Dict[str, Any]]]:
        # Only internally defined INSERT statements enter this method. Legacy
        # CLI runs without an ID keep working against the pre-GUI schema.
        if self._run_id is None:
            return query, rows
        query = query.replace("(", "(run_id, ", 1).replace(
            "VALUES (", "VALUES (%(run_id)s, ", 1
        )
        return query, [dict(row, run_id=self._run_id) for row in rows]

    def _execute_batch(
        self, cursor: Any, query: str, rows: List[Dict[str, Any]], page_size: int
    ) -> None:
        from psycopg2.extras import execute_batch

        query, tagged = self._tag_run(query, rows)
        execute_batch(cursor, query, tagged, page_size=page_size)

    def record_detection(self, row: Dict[str, Any]) -> None:
        self._execute_event(
            """
            INSERT INTO detection_events (
                ts, dpid, ipv4_src, ipv4_dst, ip_proto, l4_dst_port,
                probability, threshold, mitigation_enabled
            ) VALUES (
                %(ts)s, %(dpid)s, %(ipv4_src)s, %(ipv4_dst)s, %(ip_proto)s,
                %(l4_dst_port)s, %(probability)s, %(threshold)s,
                %(mitigation_enabled)s
            )
            """,
            row,
        )

    def record_mitigation(self, row: Dict[str, Any]) -> None:
        self._execute_event(
            """
            INSERT INTO mitigation_events (
                ts, ipv4_src, action, duration_seconds, affected_switches
            ) VALUES (
                %(ts)s, %(ipv4_src)s, %(action)s, %(duration_seconds)s,
                %(affected_switches)s
            )
            """,
            row,
        )

    def record_attack_window(
        self, start: datetime, end: datetime, attack_type: str, target_ip: str
    ) -> None:
        self._execute_event(
            """
            INSERT INTO attack_windows (start_ts, end_ts, attack_type, target_ip)
            VALUES (%(start)s, %(end)s, %(attack_type)s, %(target_ip)s)
            """,
            {
                "start": start,
                "end": end,
                "attack_type": attack_type,
                "target_ip": target_ip,
            },
        )

    def close(self) -> None:
        try:
            self.flush(force=True)
        finally:
            self._connection.close()


def create_metrics_store(
    settings: DatabaseSettings, flush_rows: int = 100
) -> MetricsStore:
    if not settings.enabled:
        return NullMetricsStore()
    return PostgreSQLMetricsStore(settings, flush_rows=flush_rows)
