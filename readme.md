# Log Analyzer Project

Build a command-line log analysis tool that can parse, filter, analyze, and report on server logs.

## Core Features

### Parsing & Data Handling
- Read log files from command line arguments
- Parse log entries into structured data (timestamp, level, component, message)
- Handle malformed log lines gracefully
- Process large files efficiently **without loading everything into memory**

### Filtering Capabilities
- Filter by log level (`INFO`, `WARN`, `ERROR`)
- Filter by component (`[web]`, `[db]`, `[auth]`, etc.)
- Filter by time ranges (start/end timestamps)
- Support chaining multiple filters simultaneously

### Analysis & Statistics
- Count entries by level and component
- Calculate time-based statistics (entries per hour/minute)
- Identify response time patterns from web logs
- Find the most common error messages

### Pattern Detection
- Detect failed login attempts (multiple failures from same IP)
- Identify slow queries/responses (configurable thresholds)
- Find security events (SQL injection attempts, rate limiting)
- Detect system health issues (high memory, CPU spikes)

### Output & Reporting
- Support multiple output formats (JSON, CSV, plain text)
- Create summary reports (error counts, response time stats, component health)
- Generate insights from detected patterns
- Export filtered results to files
- Identify potential issues worth alerting on

### Interface & Usability
- Comprehensive CLI with help text and examples
- Support chaining multiple operations in a single command
- Configuration via command line flags
- Meaningful error messages and validation

### Extensibility
Making your code easy to extend means other developers (including future you) can add new features without rewriting everything. Think of it like building with LEGO blocks - you want clean interfaces where new pieces can snap on easily.

Examples of extensibility:
- **New filters**: Someone wants to filter by IP address? They should be able to add an `IPFilter` class without touching existing code
- **New output formats**: Want XML output? Add a `XMLFormatter` without changing the core analyzer
- **New pattern detectors**: Want to detect DDoS attacks? Add a `DDoSDetector` that plugs into the existing system
- **Configuration files**: Instead of long command lines, support config files like `analyzer.config`

Good extensible design uses concepts like:
- **Plugin architecture**: New functionality can be "plugged in"
- **Configuration-driven**: Behavior can be changed without code changes
- **Modular design**: Each piece has a clear job and clean boundaries

### Success Criteria
Your tool should handle commands like:
```bash
python log_analyzer.py server.log --level ERROR --component db --format json --output errors.json
```

## Development Rules

- Use AI to understand concepts, not to write code
- Implement, however, feels natural to you
- Focus on clean, readable code
- Test with the provided log files
- Document your architectural decisions
- Your solution must handle files of varying sizes and frequencies efficiently
- Each on their own branch and no screen peaking :) have fun

## Files Provided

- `server.log` - Standard web server logs with various errors and events
- `mixed_streaming.log` - Mixed service logs with different verbosity levels
- `realtime.log` - High-frequency realtime events with microsecond timestamps
- `test.py` - you can test your code against this using cli flags
Each file presents different challenges for your architecture—choose your parsing strategy wisely!