"""
BaseAgent — ReAct loop engine for all LLM-driven agents.

Pattern: THINK → TOOL CALL → OBSERVE → repeat
The LLM decides which tools to call and in what order.
Python executes tool calls and returns observations.
The loop terminates when the LLM signals "done" or max_iterations is reached.

Usage:
    agent = BaseAgent(llm=llm_client, tool_registry=registry, system_prompt=PROMPT)
    result = agent.run(goal="Test target.com for XSS", context={"target": "target.com"})
"""
import inspect
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

REPORT_FINDING_TOOL = "report_finding"
DONE_SIGNAL = "done"

_TRUNCATE_MAX = 4000


def _truncate(d: Any, max_len: int = _TRUNCATE_MAX) -> Any:
    """Truncate any value to a string under max_len for safe LLM consumption."""
    s = json.dumps(d) if not isinstance(d, str) else d
    if len(s) > max_len:
        return s[:max_len] + f"… [truncated, {len(s) - max_len} chars omitted]"
    return s


@dataclass
class AgentResult:
    findings:        list = field(default_factory=list)
    log:             list = field(default_factory=list)
    status:          str  = "complete"   # complete | max_iterations | error
    iterations:      int  = 0
    tool_call_count: int  = 0
    summary:         str  = ""


class BaseAgent:
    """
    LLM-driven ReAct agent.

    The LLM receives a tool list and a goal. It reasons and calls tools
    iteratively. Python executes each tool call and feeds the result back.
    The LLM signals completion via {"type": "done"}.

    report_finding() calls are intercepted here — findings are captured
    internally and a confirmation is returned to the LLM so it can continue.
    """

    def __init__(
        self,
        llm,
        tool_registry: dict,
        system_prompt: str,
        max_iterations: int = int(os.getenv("AGENT_MAX_ITERATIONS", "5")),
        scope: str = None,
    ):
        self.llm            = llm
        self.tool_registry  = tool_registry   # {name: callable}
        self.system_prompt  = system_prompt
        self.max_iterations = max_iterations
        self.scope          = scope            # passed to tools that enforce scope

    def run(self, goal: str, context: dict = None) -> AgentResult:
        result   = AgentResult()
        messages = [self._build_initial_message(goal, context)]
        schemas  = self._get_tool_schemas()

        logger.info(f"[AGENT] Starting — goal: {goal[:120]}")

        for i in range(self.max_iterations):
            result.iterations = i + 1

            try:
                response = self.llm.chat_with_tools(
                    system=self.system_prompt,
                    messages=messages,
                    tools=schemas,
                )
            except Exception as e:
                logger.error(f"[AGENT] LLM error on iteration {i+1}: {e}")
                result.status = "error"
                result.log.append({"iteration": i + 1, "error": str(e)})
                break

            resp_type = response.get("type", "")

            if resp_type == DONE_SIGNAL:
                result.status  = "complete"
                result.summary = response.get("content", "")
                result.log.append({"iteration": i + 1, "type": "done"})
                logger.info(f"[AGENT] Done after {i+1} iterations — "
                            f"{result.tool_call_count} tool calls, "
                            f"{len(result.findings)} findings")
                break

            if resp_type == "tool_call":
                tool_name = response.get("tool", "")
                tool_args = response.get("args", {})
                thinking  = response.get("thinking", "")

                result.tool_call_count += 1
                log_entry = {
                    "iteration": i + 1,
                    "tool":      tool_name,
                    "args":      tool_args,
                    "thinking":  thinking,
                }

                if tool_name == REPORT_FINDING_TOOL:
                    observation = self._capture_finding(tool_args, result)
                else:
                    observation = self._execute_tool(tool_name, tool_args)

                log_entry["observation"] = _truncate(observation)
                result.log.append(log_entry)

                # Append assistant turn + observation to message history
                messages.append({
                    "role":    "assistant",
                    "content": json.dumps(response),
                })
                messages.append({
                    "role":    "user",
                    "content": self._serialise_result(observation),
                })

                # Trim history to prevent context overflow on providers with small windows.
                # Always keep messages[0] (initial goal) + the last AGENT_HISTORY messages.
                _keep = int(os.getenv("AGENT_HISTORY", "8"))
                if len(messages) > _keep + 1:
                    messages = messages[:1] + messages[-_keep:]

                logger.debug(f"[AGENT] iter={i+1} tool={tool_name} "
                             f"observation_len={len(str(observation))}")
                continue

            # LLM returned plain text — treat as an intermediate reasoning step,
            # not a termination signal; feed it back so the LLM continues.
            result.log.append({"iteration": i + 1, "type": "message",
                                "content": response.get("content", "")})
            messages.append({
                "role":    "assistant",
                "content": response.get("content", ""),
            })
            messages.append({
                "role":    "user",
                "content": "Continue. Call the next tool or signal done.",
            })

        else:
            result.status = "max_iterations"
            logger.warning(f"[AGENT] Reached max_iterations={self.max_iterations}")

        return result

    # ── Tool execution ─────────────────────────────────────────────────────────

    def _execute_tool(self, name: str, args: dict) -> Any:
        fn = self.tool_registry.get(name)
        if fn is None:
            logger.warning(f"[AGENT] Unknown tool: {name}")
            return {"error": f"Unknown tool '{name}'. Available: {list(self.tool_registry)}"}

        try:
            # Only pass scope to tools whose signature actually accepts it
            if self.scope is not None and "scope" in inspect.signature(fn).parameters:
                return fn(scope=self.scope, **args)
            return fn(**args)
        except TypeError as e:
            # Bad args from LLM — return error so LLM can correct
            logger.warning(f"[AGENT] Tool {name} bad args: {e}")
            return {"error": f"Tool '{name}' called with invalid arguments: {e}"}
        except Exception as e:
            logger.error(f"[AGENT] Tool {name} raised: {e}", exc_info=True)
            return {"error": f"Tool '{name}' failed: {e}"}

    def _capture_finding(self, args: dict, result: AgentResult) -> dict:
        """Validate and capture a report_finding() call internally."""
        required = {"name", "severity", "evidence", "remediation"}
        missing  = required - args.keys()
        if missing:
            return {"status": "rejected", "reason": f"Missing required fields: {missing}"}

        valid_severities = {"Critical", "High", "Medium", "Low", "Info"}
        if args.get("severity") not in valid_severities:
            return {
                "status": "rejected",
                "reason": f"Invalid severity '{args.get('severity')}'. "
                          f"Must be one of: {valid_severities}",
            }

        result.findings.append(dict(args))
        logger.info(f"[AGENT] Finding captured: [{args.get('severity')}] {args.get('name')}")
        return {"status": "accepted", "finding_id": len(result.findings)}

    # ── Schema and message helpers ─────────────────────────────────────────────

    def _get_tool_schemas(self) -> list:
        """Collect __schema__ from each registered tool function."""
        schemas = []
        for name, fn in self.tool_registry.items():
            schema = getattr(fn, "__schema__", None)
            if schema:
                schemas.append(schema)
            else:
                # Minimal fallback schema so the LLM at least knows the tool exists
                schemas.append({
                    "name":        name,
                    "description": fn.__doc__ or name,
                    "parameters":  {"type": "object", "properties": {}, "required": []},
                })
        return schemas

    @staticmethod
    def _build_initial_message(goal: str, context: dict = None) -> dict:
        body = f"Goal: {goal}"
        if context:
            body += f"\n\nContext:\n{json.dumps(context, indent=2)}"
        return {"role": "user", "content": body}

    @staticmethod
    def _serialise_result(result: Any) -> str:
        try:
            raw = json.dumps(result, indent=2)
        except (TypeError, ValueError):
            raw = str(result)
        return f"Tool result:\n{_truncate(raw)}"
