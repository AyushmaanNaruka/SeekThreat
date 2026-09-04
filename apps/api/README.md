# apps/api

FastAPI backend.

```
routers/     HTTP endpoints
core/        config, auth, dependencies
tasks/       Celery jobs
```

**Authorization is enforced here, not in the UI.** Every scan endpoint validates an
authorization record before dispatching. A UI-only check is not a check.

Every scan and query is logged with actor, target, authorization reference, timestamp.

## Dependencies

Dependencies live in the repository root: `requirements.txt` and `requirements-dev.txt`.
Install from the root, not from here.

    pip install -r requirements-dev.txt

