from harness import STATE, compose


def pytest_sessionfinish(session, exitstatus):
    if exitstatus:
        result = compose('logs', '--no-color', check=False)
        (STATE / 'containers.log').write_text(result.stdout + result.stderr)
