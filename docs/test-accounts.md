# Test accounts: testers that sign in

By default a tester starts signed out and tries to create an account, as a new user would.
When your app has no open sign-up, or when what you want tested is behind the sign-in
screen, give the testers accounts: one per role (owner, manager, rep...), and say which
persona signs in as which role.

Use accounts made for testing, on a test environment. A tester taps everywhere: it may
change or delete whatever its account can reach.

## Set them up

As text, the quick way:

1. Copy `accounts.example.txt` to `accounts.txt` and put your test accounts in it, one per line:

   ```
   # role   user name or phone   password   personas that sign in as it
   owner    owner@test.example   ........   anna,clara
   rep      0500000001           ........   malik
   ```

2. Run `python3 scripts/accounts.py set` (Windows: `python scripts\accounts.py set`).

Without an `accounts.txt`, the same command asks for each account in the terminal instead, the
password hidden. The setup (`setup.sh`, `setup.ps1`) runs it too, if you answer yes to its question.

- `accounts.txt` stays on your machine. Git ignores that name, and the command refuses a file
  that git could commit: your testers repo is public, and a file in it is readable by anyone.
  Keep it to change an account later, or delete it once the command has run.
- The accounts go to the `TEST_ACCOUNTS` secret of your repo, through `gh secret set`. The
  runs read that secret, never the file.
- The roles go to `personas.json`: `"account": "owner"` in each persona that signs in. A
  persona without it starts signed out, as before. Commit that file.
- GitHub never gives a secret back: to change one account, change the file (or answer the
  questions again) and run the command again, with all the accounts.

## What happens in a run

1. Before the agent starts, the workflow keeps the account of that persona's role, and only
   that one, in a folder that belongs to root on the runner. The secret is given to that step
   alone: the agent's own step never has it.
2. The agent is told that an account is ready and how to use it: tap the user name field,
   run `python3 /opt/ba3tration/account.py username`, tap the password field, run
   `... password`. These commands type the value into the focused field.
3. The agent never gets the values. Its tools cannot open the folder, and the commands and
   the typing tool they use are copies in that same folder, which it cannot edit.

## What this does not hide

- A user name is on the screen once typed, so it is in the screenshots and can be in the
  report. Both are encrypted with your key like every result.
- A password is on the screen too when the app shows it (an eye button).
- The model sees the screens, so it sees what the account can see. Do not give a tester an
  account that reaches real customers' data.

## Limits

- Sign-in with a user name and a password only. A code sent by SMS, e-mail or a messaging
  app does not reach an emulator: for such an app, give your test environment test accounts
  with a fixed code.
- On Android the typing tool types plain Latin letters, digits and signs only.
- A path replayed without a model (`replay_traces`) holds the step under a name, not the
  value: give the values in `REPLAY_PARAMS` (see [replay.md](replay.md)).
- The live scan (ZAP) still runs signed out.
