# NullSec JuliaProbe - Statistical Anomaly Detector
# Julia security tool demonstrating:
#   - Multiple dispatch
#   - Type system
#   - Array broadcasting
#   - Statistical computing
#   - Metaprogramming
#   - High-performance numerics
#
# Author: bad-antics
# License: MIT

const VERSION = "1.0.0"

# ANSI Colors
const COLORS = Dict(
    :red => "\e[31m",
    :green => "\e[32m",
    :yellow => "\e[33m",
    :cyan => "\e[36m",
    :gray => "\e[90m",
    :reset => "\e[0m"
)

colorize(color::Symbol, text) = "$(COLORS[color])$text$(COLORS[:reset])"

# Risk levels
@enum RiskLevel begin
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0
end

# Abstract type for anomaly detectors
abstract type AnomalyDetector end

# Statistical methods
struct ZScoreDetector <: AnomalyDetector
    threshold::Float64
end

struct IQRDetector <: AnomalyDetector
    multiplier::Float64
end

struct MADDetector <: AnomalyDetector
    threshold::Float64
end

struct IsolationForestDetector <: AnomalyDetector
    contamination::Float64
end

# Network event structure
struct NetworkEvent
    timestamp::Float64
    source_ip::String
    dest_ip::String
    dest_port::Int
    bytes::Int
    packets::Int
    duration::Float64
    protocol::String
end

# Anomaly finding
struct Anomaly
    event::NetworkEvent
    detector_type::String
    score::Float64
    risk::RiskLevel
    description::String
    mitre::String
end

# Multiple dispatch for detection
function detect(detector::ZScoreDetector, values::Vector{Float64})
    μ = mean(values)
    σ = std(values)
    σ == 0 && return Float64[]
    z_scores = abs.((values .- μ) ./ σ)
    return z_scores
end

function detect(detector::IQRDetector, values::Vector{Float64})
    q1 = quantile(values, 0.25)
    q3 = quantile(values, 0.75)
    iqr = q3 - q1
    lower = q1 - detector.multiplier * iqr
    upper = q3 + detector.multiplier * iqr
    # Return distance from normal range
    return [v < lower ? lower - v : (v > upper ? v - upper : 0.0) for v in values]
end

function detect(detector::MADDetector, values::Vector{Float64})
    med = median(values)
    mad = median(abs.(values .- med))
    mad == 0 && return Float64[]
    return abs.((values .- med) ./ (1.4826 * mad))
end

function detect(detector::IsolationForestDetector, values::Vector{Float64})
    # Simplified isolation score based on value extremity
    μ = mean(values)
    range_val = maximum(values) - minimum(values)
    range_val == 0 && return Float64[]
    return abs.((values .- μ) ./ range_val)
end

# Helper statistics
mean(x) = sum(x) / length(x)
std(x) = sqrt(sum((x .- mean(x)).^2) / (length(x) - 1))
median(x) = (sorted = sort(x); n = length(sorted); 
             n % 2 == 1 ? sorted[(n+1)÷2] : (sorted[n÷2] + sorted[n÷2+1])/2)
quantile(x, p) = (sorted = sort(x); n = length(sorted); 
                  idx = p * (n - 1) + 1; 
                  floor_idx = floor(Int, idx);
                  ceil_idx = ceil(Int, idx);
                  floor_idx == ceil_idx ? sorted[floor_idx] : 
                  sorted[floor_idx] * (ceil_idx - idx) + sorted[ceil_idx] * (idx - floor_idx))

# Risk assessment
function assess_risk(score::Float64)::RiskLevel
    score > 4.0 && return CRITICAL
    score > 3.0 && return HIGH
    score > 2.0 && return MEDIUM
    score > 1.0 && return LOW
    return INFO
end

# Anomaly classification
function classify_anomaly(event::NetworkEvent, score::Float64)
    if event.bytes > 100_000_000
        return ("Data Exfiltration", "T1048")
    elseif event.packets > 10000 && event.duration < 1.0
        return ("Port Scan", "T1046")
    elseif event.dest_port in [4444, 5555, 6666, 31337]
        return ("C2 Communication", "T1071")
    elseif event.duration > 3600 && event.bytes > 1_000_000
        return ("Persistent Connection", "T1095")
    elseif score > 3.5
        return ("Statistical Anomaly", "T1571")
    else
        return ("Unusual Activity", "")
    end
end

# Demo data generation
function generate_demo_events()
    events = NetworkEvent[]
    
    # Normal traffic baseline
    for i in 1:50
        push!(events, NetworkEvent(
            Float64(i),
            "192.168.1.$(rand(1:254))",
            "10.0.0.$(rand(1:10))",
            rand([80, 443, 8080, 22]),
            rand(1000:50000),
            rand(10:100),
            rand() * 10,
            rand(["TCP", "UDP"])
        ))
    end
    
    # Anomalous events
    push!(events, NetworkEvent(
        51.0, "192.168.1.100", "185.220.101.1", 4444,
        500_000_000, 50000, 0.5, "TCP"
    ))  # Data exfil
    
    push!(events, NetworkEvent(
        52.0, "45.33.32.156", "10.0.0.5", 31337,
        5000, 20, 7200.0, "TCP"
    ))  # C2 beacon
    
    push!(events, NetworkEvent(
        53.0, "192.168.1.50", "10.0.0.10", 80,
        100, 50000, 0.1, "TCP"
    ))  # Port scan
    
    push!(events, NetworkEvent(
        54.0, "10.0.0.20", "203.0.113.50", 443,
        200_000_000, 100000, 300.0, "TCP"
    ))  # Large transfer
    
    push!(events, NetworkEvent(
        55.0, "192.168.1.200", "10.0.0.5", 5555,
        10000, 500, 3700.0, "TCP"
    ))  # Persistent conn
    
    return events
end

# Analysis engine
function analyze_events(events::Vector{NetworkEvent})
    anomalies = Anomaly[]
    
    # Extract feature vectors
    bytes_vec = Float64[e.bytes for e in events]
    packets_vec = Float64[e.packets for e in events]
    duration_vec = Float64[e.duration for e in events]
    
    # Apply multiple detectors
    detectors = [
        (ZScoreDetector(3.0), "Z-Score"),
        (IQRDetector(1.5), "IQR"),
        (MADDetector(3.0), "MAD")
    ]
    
    for (detector, name) in detectors
        # Detect on bytes
        scores = detect(detector, bytes_vec)
        for (i, score) in enumerate(scores)
            if score > 2.0
                (desc, mitre) = classify_anomaly(events[i], score)
                push!(anomalies, Anomaly(
                    events[i], name, score, assess_risk(score), desc, mitre
                ))
            end
        end
        
        # Detect on packets
        p_scores = detect(detector, packets_vec)
        for (i, score) in enumerate(p_scores)
            if score > 2.5 && !any(a -> a.event.timestamp == events[i].timestamp, anomalies)
                (desc, mitre) = classify_anomaly(events[i], score)
                push!(anomalies, Anomaly(
                    events[i], name, score, assess_risk(score), desc, mitre
                ))
            end
        end
    end
    
    # Sort by score descending
    sort!(anomalies, by = a -> -a.score)
    
    # Deduplicate by timestamp
    seen = Set{Float64}()
    unique_anomalies = Anomaly[]
    for a in anomalies
        if !(a.event.timestamp in seen)
            push!(seen, a.event.timestamp)
            push!(unique_anomalies, a)
        end
    end
    
    return unique_anomalies
end

# Risk color
function risk_color(risk::RiskLevel)
    risk == CRITICAL && return :red
    risk == HIGH && return :red
    risk == MEDIUM && return :yellow
    risk == LOW && return :cyan
    return :gray
end

# Print banner
function print_banner()
    println()
    println("╔══════════════════════════════════════════════════════════════════╗")
    println("║          NullSec JuliaProbe - Statistical Anomaly Detector       ║")
    println("╚══════════════════════════════════════════════════════════════════╝")
    println()
end

# Print usage
function print_usage()
    println("USAGE:")
    println("    juliaprobe [OPTIONS] <PCAP>")
    println()
    println("OPTIONS:")
    println("    -h, --help       Show this help")
    println("    -t, --threshold  Detection threshold")
    println("    -m, --method     Detection method (zscore/iqr/mad)")
    println("    -o, --output     Output format")
    println()
    println("FEATURES:")
    println("    • Multiple detection methods")
    println("    • Statistical anomaly scoring")
    println("    • MITRE ATT&CK mapping")
    println("    • High-performance analysis")
end

# Print anomaly
function print_anomaly(anomaly::Anomaly)
    col = risk_color(anomaly.risk)
    risk_str = string(anomaly.risk)
    
    println()
    println("  $(colorize(col, "[$risk_str]")) $(anomaly.description)")
    println("    Detector:  $(anomaly.detector_type)")
    println("    Score:     $(round(anomaly.score, digits=2))")
    println("    Source:    $(anomaly.event.source_ip)")
    println("    Target:    $(anomaly.event.dest_ip):$(anomaly.event.dest_port)")
    println("    Bytes:     $(anomaly.event.bytes)")
    println("    MITRE:     $(anomaly.mitre)")
end

# Print summary
function print_summary(anomalies::Vector{Anomaly}, total_events::Int)
    critical = count(a -> a.risk == CRITICAL, anomalies)
    high = count(a -> a.risk == HIGH, anomalies)
    medium = count(a -> a.risk == MEDIUM, anomalies)
    
    println()
    println(colorize(:gray, "═══════════════════════════════════════════"))
    println()
    println("  Summary:")
    println("    Events Analyzed: $total_events")
    println("    Anomalies Found: $(length(anomalies))")
    println("    Critical:        $(colorize(:red, string(critical)))")
    println("    High:            $(colorize(:red, string(high)))")
    println("    Medium:          $(colorize(:yellow, string(medium)))")
end

# Demo mode
function demo()
    println(colorize(:yellow, "[Demo Mode]"))
    println()
    println(colorize(:cyan, "Analyzing network traffic for anomalies..."))
    
    events = generate_demo_events()
    anomalies = analyze_events(events)
    
    for a in anomalies
        print_anomaly(a)
    end
    
    print_summary(anomalies, length(events))
end

# Main entry point
function main(args=ARGS)
    print_banner()
    
    if isempty(args) || "-h" in args || "--help" in args
        print_usage()
        println()
        demo()
    elseif "--demo" in args
        demo()
    else
        print_usage()
    end
end

# Run
main()
