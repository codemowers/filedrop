# Agent instructions

<!-- codemowers/agent task 84ac6be4-401f-419e-993d-00c8cd8f0eee -->
## Agent workspace context

- Read [the task specification](specs/filedrop-84ac6be4.md) before planning. Keep it updated when the user changes requirements.
- Read [Skaffold defaults](skaffold.env). Use the worker environment and existing kubeconfig; credentials are mounted separately.
- MCP scopes: codemowers for engineering guidance, driftmower for cluster capabilities/inventory/logs/metrics, agent for namespace configuration and current task controls.
- codemowers: https://mcp.codemowers.io/mcp
- driftmower: https://mcp.driftmower.ee-lte-1.codemowers.io/mcp
- Use driftmower.query_logs for application/build logs before kubectl logs. Query admission policies and resource schemas before platform manifests.
- Validate skaffold.yaml with agent.validate_skaffold_config. Read agent.get_task_context before actions governed by user controls.
- Prefer Kaniko through Skaffold cluster builds: skaffold build or skaffold run. If configuration is missing, adapt agent.get_skaffold_example and validate it first. Report failed/unclear infrastructure instead of improvising Kaniko Pods or Jobs; direct invocation requires an explicitly requested, verified workflow.
- Infrastructure uncertainty is a blocker: report it through agent.report_blocked. Do not guess builders, registries, credentials, privileges or public visibility.
- Work in topic branches. Do not push directly to main/master, force-push, or create a remote without user direction.
