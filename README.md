# Private Invite Chat MVP

A minimal Flask chat app with:

- email/password registration
- strict invite-only account creation
- admin invite-code generation (optional email binding)
- private authenticated chat feed

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY='replace-me'
export ADMIN_INVITE_KEY='replace-me-too'
python app.py
```

Open http://localhost:5000

### MVP flow

1. Go to `/admin/invite` and generate an invite code using `ADMIN_INVITE_KEY`.
2. Share that code privately.
3. Invitee registers at `/register` using their email + password + invite code.
4. User logs in and joins `/chat`.

## Notes

- This is an MVP: admin route should be protected further for production use.
- DB is SQLite (`chat.db` by default).
