from main import AppHandler  # Import your Flask app instance

app = AppHandler.app  # Get the Flask app instance

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=2000, debug=True)