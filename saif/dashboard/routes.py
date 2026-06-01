"""Dashboard route registration compatibility module.

The v1 dashboard keeps route registration in ``app.py`` so the local UI remains
single-file simple. Import ``mount_routes`` when callers want the explicit
routes module from the dashboard package layout.
"""


def mount_routes(app):
    from saif.dashboard.app import add_api_routes

    return add_api_routes(app)
