# Start bypass for HTTP mocking
Application.ensure_all_started(:bypass)

# Start the SDK application for testing
Application.ensure_all_started(:prismatic_sdk)

ExUnit.start(exclude: [:integration, :skip_ci])