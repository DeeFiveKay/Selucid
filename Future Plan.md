### **What SHOULD be added to Selucid?**

**1. "Sandbox & What-If" Simulator (Highly Useful)**

* **Idea:** Before executing a `semanage` or `setsebool` command, Selucid shows a precise diff: what changes in the system state and which other processes are affected by the modification.
* **Why:** Toggling an SELinux boolean can unknowingly grant permissions to other services as well. A simulator removes the fear of running commands blindly.

**2. Container Integration (Podman & Flatpak)**

* **Idea:** A dedicated view for container (`container_t`) and Flatpak denial events.
* **Why:** Most modern SELinux issues on Fedora and RHEL occur when someone forgets to add the `:z` or `:Z` volume mount flag to a Podman container. Selucid can detect this automatically and suggest the correct Podman command.

**3. Proactive Context Inspection (Directory Inspector)**

* **Idea:** You can select a directory (e.g., `/var/www/my-app`) and Selucid checks whether its files have the correct SELinux contexts relative to the default system policy (`matchpathcon`).
* **Why:** Fixes issues before the application throws an error in production.

**4. Exporting & Reporting (Export for Sysadmins & CI/CD)**

* **Idea:** Ability to export denial reports as clean PDF or Markdown documents, or generate a ready-to-run Ansible playbook / Bash script.
* **Why:** A developer can diagnose the fix on their local machine and hand over a ready-made Ansible role directly to the system administrator.

**5. Fix History & Rollback System**

* **Idea:** Selucid maintains an internal audit log of all changes executed through it (e.g., modified booleans, altered file contexts) and provides a single-click/single-command **Rollback** function.
* **Why:** If a change fails to resolve the issue or inadvertently exposes too many privileges, you can instantly revert the system state back to its exact condition prior to the action.

**6. CIS & Red Hat Hardening Compliance Checks**

* **Idea:** A compliance view that audits whether the current system SELinux status aligns with official enterprise security standards (e.g., verifying `Enforcing` mode, identifying active permissive domains, or listing custom loaded `.pp` policy modules).
* **Why:** Adds high value for enterprise environments and sysadmins required to audit production RHEL servers.

**7. Security Anomaly Detection**

* **Idea:** If a specific process (such as a web server targeted by an attack) suddenly generates hundreds of `AVC denial` events per second, Selucid flags it as a critical security incident rather than a routine configuration mismatch.
* **Why:** Helps administrators distinguish developer configuration mistakes from active exploitation attempts.

---

### **What SHOULD NOT be added to Selucid? (To be honest)**

* **No custom SELinux policy compiler from scratch**
* **Why:** Writing custom `.te` (Type Enforcement) modules from the ground up is extremely complex. Rely on the system's native `audit2allow` tool under the hood instead of building a custom compiler.


* **No general system monitoring (CPU/RAM/Systemd)**
* **Why:** Tools like `htop`, `btop`, and GNOME Resources already handle this. Selucid will lose its clear identity if it tries to become a bloated all-in-one dashboard.


* **No background auto-remediation without user confirmation**
* **Why:** Automatically loosening security policies in the background is a major security risk. A user or administrator must always explicitly review and confirm any changes.


* **No built-in graphical code editor for `.te` policy files**
* **Why:** System engineers who write raw SELinux policies already use specialized editors like VS Code or Neovim with language syntax extensions.


* **No built-in remote SSH agent engine in the initial release**
* **Why:** Implementing custom authentication and connection layers introduces unnecessary attack surfaces. Running Selucid directly on target machines over SSH via the terminal UI (`selucid-tui`) is safer and simpler for v1.0.