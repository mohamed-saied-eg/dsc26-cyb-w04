## Tools
I used Claude (Anthropic) as a tutor to walk through the task step by step: the design of each function in triage/core.py and the CLI. I ran the tests and the CLI myself on my machine.

## What AI got wrong
- It suggested the Linux command `ls` and `source .venv/bin/activate`, which do not work in Windows CMD. I had to use `dir` and `.venv\Scripts\activate`.
- It first told me to download a starter zip from the task page, but there was no download link. The task actually uses a template repository, so I had to create my repo from the template instead.

## In my own words
1. Why fix `DB_PASSWORD` first?
It's an active production credential exposed in Git, posing an immediate risk. MD5 in `etag()` is just a false positive for HTTP caching (and remember to rotate the password since it's in the commit history).
2. Why must a suppression have an expiration date?
Code changes over time, making old justifications invalid. An expiration date forces the team to review and properly fix the security issue later instead of forgetting it.