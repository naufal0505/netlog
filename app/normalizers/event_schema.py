def make_event(source, event_type, host, severity, data):
    return {
        "source": source,
        "event_type": event_type,
        "host": host,
        "severity": severity,
        "data": data,
    }