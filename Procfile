web: gunicorn -w 4 -b 0.0.0.0:$PORT web.app:app
collector: python scripts/run_collection.py --skip-nvd