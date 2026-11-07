# SYNTHETIC FIXTURE - fake values for scanner testing only, not real credentials.
# Vulnerable sample: hardcoded chat bot token.
BOT_TOKEN = "SLACK_TOKEN_REDACTED"

def client
  { token: BOT_TOKEN }
end