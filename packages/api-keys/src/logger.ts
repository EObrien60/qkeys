export type LogLevel = "debug" | "info" | "warn" | "error"
export type LogFields = Record<string, unknown>

export type Logger = {
  level: LogLevel
  debug(msg: string, fields?: LogFields): void
  info(msg: string, fields?: LogFields): void
  warn(msg: string, fields?: LogFields): void
  error(msg: string, fields?: LogFields): void
}

const ORDER: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 }

/**
 * Minimal structured JSON logger. One line per event, warn/error to stderr.
 * Deliberately dependency-free; swap for pino/whatever at the app edge if wanted.
 *
 * NB: callers must never pass a raw key / Authorization header into log fields.
 * The client only ever logs key ids and prefixes, never secrets.
 */
export function createLogger(level: LogLevel = "info"): Logger {
  const threshold = ORDER[level] ?? ORDER.info

  const emit = (l: LogLevel, msg: string, fields?: LogFields) => {
    if (ORDER[l] < threshold) return
    const line = { level: l, time: new Date().toISOString(), msg, ...(fields ?? {}) }
    const out = l === "warn" || l === "error" ? process.stderr : process.stdout
    out.write(`${JSON.stringify(line)}\n`)
  }

  return {
    level,
    debug: (m, f) => emit("debug", m, f),
    info: (m, f) => emit("info", m, f),
    warn: (m, f) => emit("warn", m, f),
    error: (m, f) => emit("error", m, f),
  }
}
