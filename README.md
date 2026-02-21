# dpas
My take on trying to make safe file encryption. 

### 💡 The Concept: Ciphertext Indistinguishability
The core idea behind this tool is the **Absence of a Verification Oracle**. 

When you encrypt a standard file (like a PDF or ZIP), the software needs a way to know if the decryption password was correct. It usually does this by checking file headers (e.g., looking for the `b'%PDF'` signature) or an exposed hash. If an attacker is brute-forcing your file, the moment their script hits the right password, the software recognizes the header and flags a "Success!".

**`dpas` removes this feedback loop.**

It uses a double-encryption "onion" architecture:
1. **Inner Layer:** The file data and an internal verification hash are encrypted using a **Secondary Password**.
2. **Outer Layer:** The entire inner package is then encrypted again using a **Primary Password**.

### 🛡️ Why is this hard to crack?
Let's say you use two passwords: 
* Primary: `NoOne` 
* Secondary: `BelievesTheFlatEarthTheory`

If an attacker tries to brute-force the Primary Password, the output is just a different set of random bytes (AES noise). Because the internal verification hash is hidden inside the *second* encryption layer, **the attacker never gets a confirmation that they successfully decrypted the first layer.** To know if they succeeded, they would have to successfully guess *both* passwords simultaneously. Even if they try to pre-compute hashes or use rainbow tables for the secondary password, the sheer combinatorial explosion of guessing both layers without intermediate feedback makes brute-forcing harder.

### 🚧 Missing / Roadmap (Work in Progress)
* [ ] **Integrity Check:** 
* [ ] **Stronger Key Derivation:** Increase `scrypt` cost parameters (e.g., CPU cost `N=16384` or higher) to drastically slow down GPU brute-force attacks.
* [ ] **Memory Hygiene:**
