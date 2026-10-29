# Brouette-Jacket

The app reads `config.json` from the working directory at startup. The process exits if the file is missing or if `users` is absent. `*.json` is gitignored, so create this file locally and do not commit it.

## config.json

The file is a JSON object with one required key, `users`. Each entry is a username mapped to a [Werkzeug](https://werkzeug.palletsprojects.com/) password hash. Those credentials protect `/rickrollcounter` with HTTP basic auth.

```json
{
  "users": {
    "alice": "<werkzeug password hash>"
  }
}
```

Add one key per person who should be able to sign in. Usernames are matched exactly.

Generate a hash with the helper, which hashes the fixed password `password`:

```bash
python generate_hash.py
```

For any other password:

```bash
python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('your-password'))"
```

Paste the printed hash as the value for that username. Store the hash, not the password.

`logs.json` is separate. The app creates it to record visits, and it is not part of the config.
