type LogLevel = "debug" | "info" | "warn" | "error";

const LOG_LEVELS: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

const currentLevel: LogLevel =
  (process.env.LOG_LEVEL as LogLevel) ?? "info";

function shouldLog(level: LogLevel): boolean {
  return LOG_LEVELS[level] >= LOG_LEVELS[currentLevel];
}

export const logger = {
  debug(msg: string, data?: Record<string, unknown>): void {
    if (shouldLog("debug")) console.debug(JSON.stringify({ level: "debug", msg, ...data }));
  },
  info(msg: string, data?: Record<string, unknown>): void {
    if (shouldLog("info")) console.log(JSON.stringify({ level: "info", msg, ...data }));
  },
  warn(msg: string, data?: Record<string, unknown>): void {
    if (shouldLog("warn")) console.warn(JSON.stringify({ level: "warn", msg, ...data }));
  },
  error(msg: string, data?: Record<string, unknown>): void {
    if (shouldLog("error")) console.error(JSON.stringify({ level: "error", msg, ...data }));
  },
};
