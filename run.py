from cyber_resilient_cloud.api.app import app


if __name__ == "__main__":
    # Keep a single foreground process so terminals do not exit on reloader handoff.
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
        