# Victory Benchmarks

This directory holds automated latency profiling logs, p50/p99/p99.9
performance matrices, and loop-lag statistics.

## Latest results

The latest 256-byte durable-ACK runs offered 50,000 messages with a maximum
of 32 in-flight messages per connection. Both completed with zero errors,
missing ACKs, or enqueue failures.

| Profile | Connections | Rooms | Offered | Achieved ACKs/s | Mean ACK | p95 ACK | p99 ACK |
|---|---:|---:|---:|---:|---:|---:|---:|
| Balanced latency | 100 | 10 | 1,000/s | **999.97** | **2.46 ms** | **4.72 ms** | **7.08 ms** |
| Peak throughput | 1,000 | 50 | 10,000/s | **8,166.87** | 965.10 ms | 1,845.49 ms | 2,147.48 ms |

The balanced-latency profile is the preferred baseline because it sustains the
offered rate with low tail latency. The peak-throughput profile is retained as
the highest observed durable-ACK rate, not as a low-latency target.

Latency is measured from the fixed intended send deadline to ACK completion;
unfinished offered slots are counted separately. Benchmark records should also
capture the CPython version, storage device, fsync latency, RSS, and loop lag.
