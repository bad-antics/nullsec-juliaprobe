# NullSec JuliaProbe

**Statistical Anomaly Detector** written in Julia

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/bad-antics/nullsec-juliaprobe/releases)
[![Language](https://img.shields.io/badge/language-Julia-9558b2.svg)](https://julialang.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> Part of the **NullSec** offensive security toolkit  
> Twitter: [x.com/AnonAntics](https://x.com/AnonAntics)  
> Portal: [bad-antics.github.io](https://bad-antics.github.io)

## Overview

JuliaProbe is a high-performance statistical anomaly detector for network traffic analysis. Leveraging Julia's multiple dispatch and numerical computing capabilities, it identifies suspicious patterns through Z-Score, IQR, MAD, and Isolation Forest methods.

## Julia Features Showcased

- **Multiple Dispatch**: Polymorphic detection methods
- **Type System**: Abstract types for extensibility
- **Array Broadcasting**: `.` syntax for vectorization
- **Enums**: Type-safe risk levels
- **Structs**: Immutable data structures
- **Higher-order Functions**: `map`, `filter`, `count`
- **Comprehensions**: Expressive array creation

## Detection Methods

| Method | Description | Sensitivity |
|--------|-------------|-------------|
| Z-Score | Standard deviation based | High outliers |
| IQR | Interquartile range | Robust to extremes |
| MAD | Median absolute deviation | Very robust |
| Isolation Forest | Tree-based isolation | Complex patterns |

## Anomaly Classification

| Pattern | MITRE ID | Indicators |
|---------|----------|------------|
| Data Exfiltration | T1048 | Large byte transfers |
| Port Scanning | T1046 | High packet, low duration |
| C2 Communication | T1071 | Suspicious ports (4444, 31337) |
| Persistent Conn | T1095 | Long duration sessions |
| Statistical Anomaly | T1571 | Significant deviation |

## Installation

```bash
# Clone
git clone https://github.com/bad-antics/nullsec-juliaprobe.git
cd nullsec-juliaprobe

# Run (requires Julia 1.6+)
julia juliaprobe.jl
```

## Usage

```bash
# Run demo mode
julia juliaprobe.jl --demo

# Analyze PCAP (when extended)
julia juliaprobe.jl capture.pcap

# Show help
julia juliaprobe.jl --help
```

### Options

```
USAGE:
    juliaprobe [OPTIONS] <PCAP>

OPTIONS:
    -h, --help       Show help
    -t, --threshold  Detection threshold
    -m, --method     Detection method (zscore/iqr/mad)
    -o, --output     Output format
```

## Sample Output

```
╔══════════════════════════════════════════════════════════════════╗
║          NullSec JuliaProbe - Statistical Anomaly Detector       ║
╚══════════════════════════════════════════════════════════════════╝

[Demo Mode]

Analyzing network traffic for anomalies...

  [CRITICAL] Data Exfiltration
    Detector:  Z-Score
    Score:     8.45
    Source:    192.168.1.100
    Target:    185.220.101.1:4444
    Bytes:     500000000
    MITRE:     T1048

  [HIGH] C2 Communication
    Detector:  IQR
    Score:     3.21
    Source:    45.33.32.156
    Target:    10.0.0.5:31337
    Bytes:     5000
    MITRE:     T1071

  [MEDIUM] Port Scan
    Detector:  MAD
    Score:     2.87
    Source:    192.168.1.50
    Target:    10.0.0.10:80
    Bytes:     100
    MITRE:     T1046

═══════════════════════════════════════════

  Summary:
    Events Analyzed: 55
    Anomalies Found: 5
    Critical:        2
    High:            2
    Medium:          1
```

## Code Highlights

### Multiple Dispatch for Detection
```julia
abstract type AnomalyDetector end

struct ZScoreDetector <: AnomalyDetector
    threshold::Float64
end

struct IQRDetector <: AnomalyDetector
    multiplier::Float64
end

function detect(detector::ZScoreDetector, values::Vector{Float64})
    μ = mean(values)
    σ = std(values)
    return abs.((values .- μ) ./ σ)
end

function detect(detector::IQRDetector, values::Vector{Float64})
    q1 = quantile(values, 0.25)
    q3 = quantile(values, 0.75)
    iqr = q3 - q1
    # ...
end
```

### Vectorized Operations
```julia
# Broadcasting with dot syntax
z_scores = abs.((values .- μ) ./ σ)

# Array comprehension
distances = [v < lower ? lower - v : (v > upper ? v - upper : 0.0) 
             for v in values]
```

### Type-safe Enums
```julia
@enum RiskLevel begin
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0
end
```

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                   JuliaProbe Architecture                      │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│    │  Network    │───▶│  Feature    │───▶│  Vector     │      │
│    │  Events     │    │  Extraction │    │  Arrays     │      │
│    └─────────────┘    └─────────────┘    └──────┬──────┘      │
│                                                  │             │
│         ┌────────────────┬─────────────┬────────┘             │
│         ▼                ▼             ▼                       │
│    ┌─────────┐     ┌─────────┐   ┌─────────┐                  │
│    │ Z-Score │     │   IQR   │   │   MAD   │                  │
│    │ Detect  │     │ Detect  │   │ Detect  │                  │
│    └────┬────┘     └────┬────┘   └────┬────┘                  │
│         │               │              │                       │
│         └───────────────┼──────────────┘                       │
│                         ▼                                      │
│                ┌─────────────────┐                             │
│                │    Classify     │                             │
│                │    & Report     │                             │
│                └─────────────────┘                             │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

## Why Julia?

| Requirement | Julia Advantage |
|-------------|-----------------|
| High Performance | Near-C speed |
| Numerical Computing | Native support |
| Multiple Dispatch | Flexible polymorphism |
| Broadcasting | Vectorized operations |
| Type System | Performance + safety |
| REPL | Interactive development |

## License

MIT License - See [LICENSE](LICENSE) for details.

## Related Tools

- [nullsec-flowtrace](https://github.com/bad-antics/nullsec-flowtrace) - Flow analyzer (Haskell)
- [nullsec-beaconhunt](https://github.com/bad-antics/nullsec-beaconhunt) - Beacon detector (Elixir)
- [nullsec-cryptoaudit](https://github.com/bad-antics/nullsec-cryptoaudit) - Crypto analyzer (Scala)
