if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=int(os.getenv("PORT", "5005")))