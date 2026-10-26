---
name: Quiz-result persistence
description: The project requirement to keep leaderboard and attempt data across restarts and updates.
---

Completed quiz attempts and their leaderboard data must persist across app updates, restarts, and logouts.

**Why:** The user explicitly asked that leaderboard data remain available after updates and logouts.

**How to apply:** Do not delete or recreate quiz, question, answer, or attempt rows during app startup. Seed initial quiz content only when the database is empty; use non-destructive, explicit updates for future content changes.
