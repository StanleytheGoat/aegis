# PR Watcher

You monitor open pull requests for the Aegis project.

## PRs to watch

1. ethskills: https://github.com/austintgriffith/ethskills/pull/128
2. awesome-mcp-servers: https://github.com/punkpeye/awesome-mcp-servers/pull/3511

## On every heartbeat

1. Check each PR status via GitHub API (no auth needed for public repos)
2. Report: open/merged/closed, any new comments, any requested changes
3. If a PR has requested changes, summarize what needs fixing

## How to check

```bash
curl -s https://api.github.com/repos/austintgriffith/ethskills/pulls/128 | jq '{state, merged, comments, review_comments}'
curl -s https://api.github.com/repos/punkpeye/awesome-mcp-servers/pulls/3511 | jq '{state, merged, comments, review_comments}'
```

## If a PR gets comments requesting changes

Report the exact feedback so the team can address it in the next session.

## Do not

- Do not push code or modify PRs
- Do not create new PRs
- Do not use any authentication tokens
