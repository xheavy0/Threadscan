# vulnapp

A tiny, intentionally vulnerable web app used as the target of Threadscan's end-to-end test (`targets/demo`). Never deploy it.

    python app.py --port 8080
    python -m unittest discover -s tests
