"""Browser views never become the authoritative immutable source snapshot."""


def public_report_view(value):
    if isinstance(value, list):
        return [public_report_view(item) for item in value]
    if not isinstance(value, dict):
        return value
    result = {}
    for key, item in value.items():
        if key == "approved_input" and isinstance(item, dict):
            result[key] = {
                k: v for k, v in item.items() if k in {"snapshot_sha256", "consent_id", "policy"}
            }
        elif key == "source_events" and isinstance(item, list):
            result[key] = [
                {
                    k: public_report_view(v)
                    for k, v in event.items()
                    if k not in {"process", "network", "user"}
                }
                for event in item
            ]
        else:
            result[key] = public_report_view(item)
    return result
