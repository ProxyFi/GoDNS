### New Feature: The DNS Blocklist

The most recent update adds a powerful new feature: a **DNS Blocklist**. This feature allows your DNS server to act like a filter, preventing certain websites from being accessed by devices on your network.

Imagine your DNS server is a phone book. Normally, when you ask it for the address of a website (like `example.com`), it looks up the address and gives it to you. With the blocklist feature, you can tell your DNS server to do something different. If a domain is on your "blocklist," the server will pretend that website doesn't exist, so no one can reach it.

### How It Works: Blocklist vs. Whitelist

The feature uses two main concepts:

  * **Blocklist (Blacklist):** A list of domains that you **DO NOT** want to resolve. If a domain is on this list, your DNS server will return a "non-existent domain" error (`NXDOMAIN`), stopping the connection before it even starts. This is useful for blocking ads, malicious sites, or inappropriate content.

  * **Whitelist:** A list of domains that you **ALWAYS** want to allow, even if they might also appear on the blocklist. The whitelist takes priority. This is useful for making sure a specific site works, for example, if a part of a legitimate website is accidentally on a public blocklist.

### How to Configure and Use It

To enable and configure this feature, you need to modify the `settings.go` file. The new `Blocklist` section is where all the settings are:

```toml
[blocklist]
  enable = true
  backend = "file" # or "redis"
  file = "./etc/blocklist.txt"
  whitelist-file = "./etc/whitelist.txt"
  refresh-interval = 300 # in seconds
```

Let's break down each setting:

  * `enable`: Set this to `true` to turn on the blocklist feature.
  * `backend`: This tells the program where to get the lists from. You can choose either `"file"` (for a simple text file) or `"redis"` (for a more powerful, network-based list).
  * `file`: The path to your blocklist file.
  * `whitelist-file`: The path to your whitelist file.
  * `refresh-interval`: The number of seconds the program waits before reloading the lists from the files or Redis. This means you don't need to restart the server to update your lists.

#### Option 1: Using Text Files (`backend = "file"`)

This is the simplest way to get started.

1.  **Create your files:** In the directory where you'll run the program, create two text files (for example, `blocklist.txt` and `whitelist.txt`).

2.  **Add domains:** Open the files with a text editor and add one domain per line. You can also use a `#` at the beginning of a line to add a comment.

    **Example `blocklist.txt`:**

    ```
    # Block common ad servers
    adserver.com
    track.analytics.net
    malicious-site.io
    ```

    **Example `whitelist.txt`:**

    ```
    # Whitelist a site that might be on a public blocklist
    mybank.com
    ```

3.  **Update the settings:** Make sure the paths in your `settings.go` file match the names of your files. The program will automatically load these files when it starts and refresh them every 5 minutes (if `refresh-interval` is `300`).

#### Option 2: Using Redis (`backend = "redis"`)

This option is for more advanced users who want to manage the lists centrally on a Redis server.

1.  **Set up Redis:** Make sure your `settings.go` file has the correct Redis connection details.

2.  **Add domains to Redis:** Use Redis commands to add domains to a special list called a "Set". The program will look for two keys: one for the blocklist and one for the whitelist.

    For example, if you set `redis-key = "godns:blocklist"` and `redis-whitelist-key = "godns:whitelist"`, you would run the following commands in your Redis client:

    ```
    SADD godns:blocklist adserver.com
    SADD godns:blocklist malicious-site.io
    SADD godns:whitelist mybank.com
    ```

The `godns` server will then automatically connect to Redis, fetch the domains from these sets, and update its blocklist and whitelist.

This feature gives you a lot of control over your network's DNS behavior and is a great way to improve security and privacy.
