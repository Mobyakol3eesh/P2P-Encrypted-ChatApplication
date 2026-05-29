# P2P Encrypted Chat Application
### RSA & AES Hybrid Cryptosystem 

---

## Dependencies

**No external cryptographic libraries are used.** The only third-party dependencies are:

```
flask
requests
```

All cryptographic operations (RSA, AES, key generation, modular arithmetic) are implemented in pure Python using only the standard library.

---

## Compilation Instructions

No compilation is required. Python is an interpreted language. Simply ensure Python 3.8 or higher is installed.

Install dependencies:

```bash
pip install flask requests
```

---

## Run Instructions

**Step 1 — Start the Signaling Server**

```bash
python server.py
```

The server starts on `http://localhost:8000`. Keep this terminal open.

**Step 2 — Start a Peer**

```bash
python app.py
```

You will be prompted:
```
Enter your username: alice
```

To run with debug output (shows key values, encrypted bytes, hex ciphertext):
```bash
python app.py --debug
```

**Step 3 — Start a second peer in another terminal**

```bash
python app.py
# Enter your username: bob
```

---

## Example Inputs & Outputs

**Terminal 1 — Signaling Server:**
```
$ python server.py
 * Running on http://0.0.0.0:8000
```

**Terminal 2 — Alice:**
```
$ python app.py
Enter your username: alice
Generating Public & Private Keys...
Connecting to intermediate server....
Registered as alice at 192.168.1.5:5000
alice> /dm bob Hello Bob, this is a secret!
Connecting to bob...
Connected to bob
[you -> bob]: Hello Bob, this is a secret!
```

**Terminal 3 — Bob:**
```
$ python app.py
Enter your username: bob
Registered as bob at 192.168.1.5:5001
bob>
[alice connected]
press enter to continue...
[DM from alice]: Hello Bob, this is a secret!
```

**Debug mode:**
```
$ python app.py --debug
Generating Public & Private Keys...
Generated Private And Public Keys are pu(e,n)=(65537, 1234...5678) pr(d,n)=(9876...1234, 1234...5678)
Encrypting session key 3f8a...b2c1 for recipient with public key (e,n)=(65537, ...)
Encrypted session key (hex): 7e3d...a4f2
Encrypting message Hello Bob with session key: 3f8a...b2c1
Encrypted message (hex): c8f1...9a3b
```

**Group chat:**
```
alice> /create-group devteam bob,charlie
Group 'devteam' created with members: bob, charlie

alice> /dm-group devteam Sprint meeting at 3pm
[you -> devteam]: Sprint meeting at 3pm
```
