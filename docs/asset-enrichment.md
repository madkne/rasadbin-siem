# Asset enrichment (OT/IT safety model)

Rasadbin enriches assets asynchronously. Asset discovery remains a fast,
observation-driven operation; it never performs DNS, filesystem, or network
lookups inside the packet/event ingestion path.

## Current passive providers

| Provider | Evidence | Target interaction |
| --- | --- | --- |
| DNS reverse lookup | PTR record for an observed IP | DNS resolver query only; no connection to the asset |
| Linux neighbor table | Complete IPv4 ARP entries in `/proc/net/arp` | Local kernel table read only |
| Ethernet metadata | Source/destination MAC in captured Ethernet frames | Passive packet observation |
| Service fingerprint | Well-known TCP port from an observed SYN/SYN-ACK handshake | No connection or probe; port-only result has low confidence |

OT protocol ports (Modbus/TCP 502, DNP3 20000, IEC-104 2404, S7comm 102,
OPC UA 4840 and EtherNet/IP 44818) are marked as hypotheses, not proof
that a protocol is present. Parsed protocol events should later be used to raise
confidence and add stronger evidence.

The Linux neighbor provider currently reads IPv4 `/proc/net/arp`. MACs are
also extracted directly from Ethernet headers by the network collector. An
asset can therefore still get a MAC when the sensor's local ARP cache does not
contain the remote endpoint.

## Queue and lifecycle

- Bounded queue (512 IDs), deduplicated by stable asset ID.
- Two workers by default; provider calls have a 10-second overall deadline.
- Retry backoff starts at 30 seconds and caps at 30 minutes.
- States: `pending`, `enriching`, `partial`, `enriched`, `failed`.
- A newly observed port or MAC re-queues enrichment. A periodic scheduler
  retries pending/failed work after restart or queue pressure.
- Results and evidence are persisted in the existing `assets` table using
  JSON text columns, compatible with SQLite, PostgreSQL and MySQL via GORM
  AutoMigrate.
- Analyst-owned `Name`, `Tags`, and `Criticality` are never changed by merge.

## Active enrichment policy

Active enrichment is disabled by default. The admin Settings page has an
explicit `Allow active enrichment` switch and a required CIDR allowlist. The
server-side policy checks both the switch and that the asset IP is inside an
allowed prefix. An empty allowlist cannot be enabled.

No active provider is registered in this release. The policy is a fail-closed
extension point: future TCP/UDP/service probes must declare `Active() == true`
and pass the server policy before they can run. OT environments should add
maintenance windows, rate limits, per-integration exclusions, and a separate
approval/audit workflow before registering any active provider. Do not probe
PLCs, safety controllers, HMIs, or other OT endpoints automatically.
