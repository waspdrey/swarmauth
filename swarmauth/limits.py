"""Protocol lifetime and storage bounds shared by verification and backends."""

MAX_TTL_SECONDS = 30
MAX_LEEWAY_SECONDS = 2
# Integer-second verification accepts the entire exp + leeway second.
RETENTION_AFTER_EXP_SECONDS = MAX_LEEWAY_SECONDS + 1
