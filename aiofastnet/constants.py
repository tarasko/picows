# After the connection is lost, log warnings after this many write()s.
LOG_THRESHOLD_FOR_CONNLOST_WRITES = 5

# Seconds to wait before retrying accept().
ACCEPT_RETRY_DELAY = 1

# Number of seconds to wait for SSL handshake to complete
# The default timeout matches that of Nginx.
SSL_HANDSHAKE_TIMEOUT = 60.0

# Number of seconds to wait for SSL shutdown to complete
# The default timeout mimics lingering_time
SSL_SHUTDOWN_TIMEOUT = 30.0

FLOW_CONTROL_HIGH_WATER_SSL_READ = 256  # KiB
FLOW_CONTROL_HIGH_WATER_SSL_WRITE = 512  # KiB

READ_BUFFER_MAX_SIZE = 256 * 1024