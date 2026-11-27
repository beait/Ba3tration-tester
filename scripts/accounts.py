"""Test accounts for the testers: one per role, typed for them, never shown to them.

On your machine, once (and again whenever an account changes):
  python3 scripts/accounts.py set
    takes one test account per role (owner, manager, rep...), stores them all in the
    TEST_ACCOUNTS secret of this repo through `gh secret set`, and writes which persona
    signs in as which role in personas.json ("account": "<role>").
    The accounts come from accounts.txt when that file is in the folder (one line per
    account, see accounts.example.txt), and from questions in the terminal otherwise.
    accounts.txt stays on your machine: git ignores that name, and the command refuses a
    file that git could commit. Nothing is printed or sent anywhere else.

On the runner, before the agent starts (the workflow does):
  python3 scripts/accounts.py setup          env: TEST_ACCOUNTS, PERSONA, PLATFORM
    keeps the account of this persona's role only, in a folder that belongs to root:
    the agent's own tools (cat, Read) cannot open it.

By the agent, during the test (a copy of this file in that folder, so the agent cannot edit it):
  python3 /opt/ba3tration/account.py status | username | password
    username and password type the value into the focused field, with a copy of the typing
    tool that the agent cannot edit either. The agent is told what was typed, never the value.

What this does not hide: a user name is on the screen once typed, and a password is too when
the app shows it (an eye button). Screenshots and reports are encrypted like every result.
Use accounts made for testing, on a test environment: a tester taps everywhere.
"""
import getpass
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SECRET = "TEST_ACCOUNTS"
ROLE = re.compile(r"[a-z0-9][a-z0-9_-]{0,30}")
STORE = Path("/opt/ba3tration")
HELPER = "python3 %s/account.py" % STORE


# ---------------------------------------------------------------- on your machine

def ask(prompt):
    try:
        return input(prompt).strip()
    except EOFError:
        return ""


def assign(text, persona, role):
    """personas.json with "account": role in that persona, the rest of the file untouched. None when it cannot be done safely."""
    lines = text.split("\n")
    start = next((i for i, line in enumerate(lines) if re.fullmatch(r'\s*"id": %s,?\s*' % re.escape(json.dumps(persona)), line)), None)
    if start is None:
        return None
    end = next((i for i in range(start + 1, len(lines)) if re.match(r'\s*"id":', lines[i])), len(lines))
    indent = re.match(r"\s*", lines[start]).group(0)
    new = '%s"account": %s,' % (indent, json.dumps(role))
    old = next((i for i in range(start, end) if re.match(r'\s*"account":', lines[i])), None)
    if old is not None:
        if not lines[old].rstrip().endswith(","):   # last key of the persona: no comma after it
            new = new[:-1]
        lines[old] = new
    else:
        if not lines[start].rstrip().endswith(","):
            return None
        lines.insert(start + 1, new)
    out = "\n".join(lines)
    try:
        ok = any(p.get("id") == persona and p.get("account") == role for p in json.loads(out))
    except (ValueError, AttributeError, TypeError):
        ok = False
    return out if ok else None


def read_file(path):
    """accounts.txt -> ({role: account}, {role: [personas]}), or a message that names the line, never its content."""
    try:
        text = path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        return None, "%s is not UTF-8 text: in Notepad, Save as, Encoding UTF-8" % path
    except OSError:
        return None, "%s could not be read" % path
    accounts, wanted = {}, {}
    for n, line in enumerate(text.splitlines(), 1):
        fields = line.split()
        if not fields or fields[0].startswith("#"):
            continue
        if len(fields) not in (3, 4):
            return None, "%s, line %d: write  role  user-name  password  personas  (no space inside a value; the personas are optional)" % (path, n)
        role = fields[0].lower()
        if not ROLE.fullmatch(role):
            return None, "%s, line %d: a role name is made of lower-case letters, digits, - and _" % (path, n)
        if role in accounts:
            return None, "%s, line %d: the role '%s' is there twice" % (path, n, role)
        if "change-me" in fields[1:3]:
            return None, "%s, line %d: still the example's values" % (path, n)
        accounts[role] = {"username": fields[1], "password": fields[2]}
        wanted[role] = [p for p in fields[3].split(",") if p] if len(fields) == 4 else []
    return (accounts, wanted) if accounts else (None, "%s holds no account" % path)


def could_be_committed(path):
    """True when the file is in a git repo that does not ignore it: one `git add .` away from being published."""
    try:
        return subprocess.run(["git", "check-ignore", "-q", str(path)], capture_output=True).returncode == 1
    except OSError:
        return False


def ask_accounts():
    print("Test accounts for the testers, one per role.")
    print("What you type here goes to the %s secret of this repo and nowhere else." % SECRET)
    print("(Easier as text? Copy accounts.example.txt to accounts.txt, fill it, and run this again.)")
    print()
    accounts = {}
    while True:
        role = ask("Role name (for example owner, manager, rep). Empty when you are done: ").lower()
        if not role:
            break
        if not ROLE.fullmatch(role):
            print("  A role name is made of lower-case letters, digits, - and _.")
            continue
        username = ask("  User name, e-mail or phone of the '%s' test account: " % role)
        if not username:
            print("  Nothing typed: role skipped.")
            continue
        password = getpass.getpass("  Its password (hidden): ")
        if not password or password != getpass.getpass("  The password again: "):
            print("  Empty, or not the same twice: role skipped, enter it again.")
            continue
        accounts[role] = {"username": username, "password": password}
        print("  '%s' noted." % role)
    return accounts


def cmd_set(source="accounts.txt"):
    source, wanted = Path(source), None
    print("Use accounts made for testing, on a test environment: a tester taps everywhere and may")
    print("change or delete what its account can reach. This replaces the accounts saved before.")
    print()
    if source.is_file():
        if could_be_committed(source):
            print("%s is not ignored by git: one `git add .` would publish it. Add its name to .gitignore, then run this again." % source)
            return 1
        accounts, wanted = read_file(source)
        if accounts is None:
            print(wanted)
            return 1
        print("Accounts read from %s: %s." % (source, ", ".join(sorted(accounts))))
    else:
        accounts = ask_accounts()
    if not accounts:
        print("No account entered: nothing changed.")
        return 1
    if any(not (a["username"] + a["password"]).isascii() for a in accounts.values()):
        print("Note: on Android the typing tool only types plain Latin letters, digits and signs: an account")
        print("with other letters will not sign in there (it will on iOS and on the web).")
    done = subprocess.run(["gh", "secret", "set", SECRET], input=json.dumps(accounts, ensure_ascii=False).encode("utf-8"))
    roles = sorted(accounts)
    del accounts
    if done.returncode:
        print("gh could not save the secret: nothing changed. Is this the folder of your repo, and are you logged in (gh auth status)?")
        return 1
    print("Secret %s set, with the roles: %s." % (SECRET, ", ".join(roles)))

    path = Path("personas.json")
    try:
        text = path.read_text(encoding="utf-8")
        personas = [p["id"] for p in json.loads(text)]
    except (OSError, ValueError, KeyError, TypeError):
        print('personas.json could not be read: add "account": "<role>" by hand to each persona that signs in.')
        return 0
    if wanted is None:
        print()
        print("Which persona signs in as which role? A persona with no role starts signed out, as before.")
        print("Personas: %s" % ", ".join(personas))
        wanted = {role: [x.strip() for x in ask("  Personas that sign in as '%s' (comma-separated, empty for none): " % role).split(",") if x.strip()]
                  for role in roles}
    changed = []
    for role in roles:
        for persona in wanted.get(role, []):
            new = assign(text, persona, role) if persona in personas else None
            if new is None:
                print('  %s: not a persona of personas.json, or not written: add "account": "%s" to it by hand' % (persona, role))
            else:
                text = new
                changed.append("%s as %s" % (persona, role))
    if changed:
        path.write_text(text, encoding="utf-8")
        print("personas.json updated (%s)." % ", ".join(changed))
        if not os.environ.get("BA3TRATION_SETUP"):   # the setup commits it itself
            print('Commit and push it:  git add personas.json; git commit -m "Personas: test account roles"; git push')
    elif not any(wanted.values()):
        print('No persona signs in yet: give the personas in %s, or add "account": "<role>" in personas.json.' % source)
    if source.is_file():
        print()
        print("%s still holds the passwords as text, on this machine only. Keep it to change an account later," % source)
        print("or delete it: the secret is saved, the runs do not need the file.")
    return 0


# ---------------------------------------------------------------- on the runner

def sudo(*args, **kw):
    prefix = [] if os.environ.get("BA3TRATION_NO_SUDO") else ["sudo", "-n"]   # the tests have no root
    return subprocess.run(prefix + list(args), check=True, **kw)


def cmd_setup():
    store = Path(os.environ.get("BA3TRATION_STORE") or STORE)
    persona, platform = os.environ.get("PERSONA", ""), os.environ.get("PLATFORM", "")
    raw = os.environ.get(SECRET, "").strip()
    if not raw:
        print("No %s secret: the testers start signed out." % SECRET)
        return 0
    try:
        accounts = json.loads(raw)
        role = next(p for p in json.loads(Path("personas.json").read_text(encoding="utf-8")) if p.get("id") == persona).get("account")
    except (ValueError, OSError, StopIteration, AttributeError, TypeError):
        print("::warning::%s is not the JSON written by scripts/accounts.py set, or personas.json could not be read: no test account" % SECRET)
        return 0
    if not role:
        print('Persona %s has no "account" in personas.json: it starts signed out.' % persona)
        return 0
    account = accounts.get(role) if isinstance(accounts, dict) and isinstance(role, str) else None
    values = [account.get("username"), account.get("password")] if isinstance(account, dict) else []
    if len(values) != 2 or not all(isinstance(v, str) and v for v in values):
        print("::warning::Persona %s signs in as '%s', but %s holds no such account: it starts signed out. Run scripts/accounts.py set again." % (persona, role, SECRET))
        return 0
    for value in values:   # should a tool ever print one, the log shows *** in its place
        if "\n" not in value:
            print("::add-mask::%s" % value)
    sudo("rm", "-rf", str(store))
    sudo("mkdir", "-p", str(store))
    sudo("cp", "-R", "scripts", str(store / "scripts"))
    sudo("cp", "scripts/accounts.py", str(store / "account.py"))
    kept = {"role": role, "persona": persona, "platform": platform, "username": values[0], "password": values[1]}
    sudo("tee", str(store / "account.json"), input=json.dumps(kept).encode("utf-8"), stdout=subprocess.DEVNULL)
    if not os.environ.get("BA3TRATION_NO_SUDO"):
        sudo("chown", "-R", "0:0", str(store))
    sudo("chmod", "-R", "go-w", str(store))
    sudo("chmod", "600", str(store / "account.json"))
    print("Test account ready for persona %s: role '%s'. Its values are out of the agent's reach." % (persona, role))
    return 0


# ---------------------------------------------------------------- by the agent

def load(home):
    path = home / "account.json"
    try:
        text = path.read_text(encoding="utf-8")
    except PermissionError:   # the normal case on a runner: the file belongs to root
        text = subprocess.run(["sudo", "-n", "cat", str(path)], capture_output=True, text=True).stdout
    except OSError:
        return None
    try:
        account = json.loads(text)
        return account if account.get("username") and account.get("password") else None
    except (ValueError, AttributeError):
        return None


def cmd_use(what):
    home = Path(__file__).resolve().parent
    helper = "python3 %s" % Path(__file__).resolve()
    account = load(home)
    if what in ("status", "note"):
        if account:
            print("A test account is ready for you (role: %s). On the sign-in screen, tap the user name field and run "
                  "`%s username`, then tap the password field and run `%s password`: they type the values, which you "
                  "cannot see and must not look for. Sign in with it instead of creating an account. Never change its "
                  "password, e-mail or phone, and never delete it." % (account["role"], helper, helper))
        elif what == "status":
            print("No test account for this persona: start signed out.")
        return 0
    if not account:
        print("failed: no test account for this persona")
        return 1
    script = home / "scripts" / str(account.get("platform")) / "type.py"
    if not script.is_file():
        print("failed: no typing tool for this platform")
        return 1
    # Nothing the agent can edit takes part: the typing tool is the copy next to this file, and
    # folders of the checkout are dropped from PATH (on Android that is the adb that notes each step).
    work = os.path.realpath(os.getcwd())
    env = dict(os.environ)
    env["PATH"] = os.pathsep.join(p for p in env.get("PATH", "").split(os.pathsep)
                                  if p and not (os.path.realpath(p) + os.sep).startswith(work + os.sep))
    log = env.pop("ECR_ACTION_LOG", None)
    done = subprocess.run([sys.executable, str(script), account[what]], env=env, capture_output=True, text=True, errors="replace")
    if "typed:" not in done.stdout:
        said = (done.stdout + done.stderr).replace(account["username"], "***").replace(account["password"], "***")
        print("failed: the %s was not typed. %s" % (what, said.strip()[-200:]))
        return 1
    if log:   # the path keeps the step under a name, not the value: a replay gets the value from REPLAY_PARAMS
        try:
            with open(log, "a", encoding="utf-8") as f:
                f.write("0\ttype\t<%s test account: %s>\n" % (account["role"], what))
        except OSError:
            pass
    print("typed the %s of the '%s' test account: check the field on the next screenshot" % (what, account["role"]))
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    what = argv[0] if argv else ""
    if what == "set":
        return cmd_set(*argv[1:2])
    if what == "setup":
        return cmd_setup()
    if what in ("status", "note", "username", "password"):
        return cmd_use(what)
    print(__doc__.strip().split("\n\n")[0])
    print("Usage: python3 scripts/accounts.py set    (on your machine)")
    return 2


if __name__ == "__main__":
    sys.exit(main())
