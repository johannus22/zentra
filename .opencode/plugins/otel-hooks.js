// otel-hooks-opencode-plugin-v1
import { appendFileSync, mkdirSync } from "node:fs"
import { dirname, join } from "node:path"
import { tmpdir } from "node:os"
import { spawnSync } from "node:child_process"

const stateRoot = join(tmpdir(), "otel-hooks", "opencode")
const roleByMessageId = new Map()
const modelByMessageId = new Map()
const tokensByMessageId = new Map()

// Resolved once at plugin load from the OpenCode process environment.
const cwd = process.cwd()
const gitBranch = (() => {
  try {
    return spawnSync("git", ["branch", "--show-current"], { encoding: "utf8" }).stdout.trim() || ""
  } catch { return "" }
})()

function msToIso(ms) {
  return ms ? new Date(ms).toISOString() : undefined
}

function ensureParent(filePath) {
  mkdirSync(dirname(filePath), { recursive: true })
}

function transcriptPath(sessionID) {
  return join(stateRoot, `${sessionID}.jsonl`)
}

function appendJsonl(path, obj) {
  ensureParent(path)
  appendFileSync(path, JSON.stringify(obj) + "\n", "utf8")
}

function callHook(payload) {
  try {
    spawnSync("otel-hooks", ["hook"], {
      input: JSON.stringify(payload),
      encoding: "utf8",
    })
  } catch (err) {
    // ignore hook failures from plugin runtime
  }
}

function emitTrace(sessionID, path, eventType) {
  callHook({
    source_tool: "opencode",
    opencode_event_type: eventType,
    session_id: sessionID,
    transcript_path: path,
  })
}

function emitMetric(sessionID, metricName, attributes = {}) {
  callHook({
    source_tool: "opencode",
    kind: "metric",
    session_id: sessionID,
    metric_name: metricName,
    metric_value: 1,
    metric_attributes: attributes,
  })
}

function assistantMessage(messageID, content) {
  const msg = {
    id: messageID,
    role: "assistant",
    model: modelByMessageId.get(messageID) || "opencode",
    content,
  }
  const usage = tokensByMessageId.get(messageID)
  if (usage) msg.usage = usage
  return { type: "assistant", message: msg }
}

function userMessage(messageID, content) {
  return {
    type: "user",
    message: {
      id: messageID,
      role: "user",
      content,
    },
  }
}

export const OTelHooksPlugin = async () => ({
  event: async (input) => {
    const event = input?.event
    if (!event || typeof event !== "object") return

    if (event.type === "message.updated") {
      const info = event.properties?.info
      if (!info || typeof info !== "object") return
      const sessionID = typeof info.sessionID === "string" ? info.sessionID : ""
      const messageID = typeof info.id === "string" ? info.id : ""
      const role = info.role === "assistant" ? "assistant" : info.role === "user" ? "user" : ""
      if (!sessionID || !messageID || !role) return

      roleByMessageId.set(messageID, role)

      if (role === "assistant") {
        const modelID = typeof info.modelID === "string" ? info.modelID : ""
        if (modelID) modelByMessageId.set(messageID, modelID)

        const t = info.tokens
        if (t && typeof t === "object") {
          tokensByMessageId.set(messageID, {
            input_tokens: t.input ?? 0,
            output_tokens: t.output ?? 0,
            cache_read_input_tokens: t.cache?.read ?? 0,
            cache_creation_input_tokens: t.cache?.write ?? 0,
            reasoning_tokens: t.reasoning ?? 0,
          })
        }
      }

      const path = transcriptPath(sessionID)
      if (role === "assistant") {
        const entry = assistantMessage(messageID, [])
        // Use time.completed when available (final update) for turn duration calc
        const ts = info.time?.completed ?? info.time?.created
        if (ts) entry.timestamp = msToIso(ts)
        appendJsonl(path, entry)
      } else {
        const entry = userMessage(messageID, [])
        if (info.time?.created) entry.timestamp = msToIso(info.time.created)
        if (cwd) entry.cwd = cwd
        if (gitBranch) entry.gitBranch = gitBranch
        appendJsonl(path, entry)
      }
      return
    }

    if (event.type === "message.part.updated") {
      const part = event.properties?.part
      if (!part || typeof part !== "object") return
      const sessionID = typeof part.sessionID === "string" ? part.sessionID : ""
      const messageID = typeof part.messageID === "string" ? part.messageID : ""
      if (!sessionID || !messageID) return
      const path = transcriptPath(sessionID)
      const role = roleByMessageId.get(messageID)

      if (part.type === "text") {
        const text = typeof part.text === "string" ? part.text : ""
        if (role === "user") {
          const entry = userMessage(messageID, [{ type: "text", text }])
          if (cwd) entry.cwd = cwd
          if (gitBranch) entry.gitBranch = gitBranch
          appendJsonl(path, entry)
        } else {
          appendJsonl(path, assistantMessage(messageID, [{ type: "text", text }]))
        }
        return
      }

      if (part.type === "tool") {
        const toolName = typeof part.tool === "string" && part.tool ? part.tool : "unknown"
        const callID = typeof part.callID === "string" && part.callID ? part.callID : messageID
        const state = part.state && typeof part.state === "object" ? part.state : {}
        const inputObj = state.input && typeof state.input === "object" ? state.input : {}
        appendJsonl(
          path,
          assistantMessage(messageID, [
            { type: "tool_use", id: callID, name: toolName, input: inputObj },
          ]),
        )

        const status = typeof state.status === "string" ? state.status : ""
        if (status === "running") {
          emitMetric(sessionID, "tool_started", { tool_name: toolName })
        }
        if (status === "completed") {
          const output = typeof state.output === "string" ? state.output : JSON.stringify(state.output ?? "")
          appendJsonl(
            path,
            userMessage(`${messageID}:${callID}:result`, [
              { type: "tool_result", tool_use_id: callID, content: output },
            ]),
          )
          emitMetric(sessionID, "tool_completed", { tool_name: toolName })
        }
        if (status === "error") {
          const err = typeof state.error === "string" ? state.error : "tool_error"
          appendJsonl(
            path,
            userMessage(`${messageID}:${callID}:result`, [
              { type: "tool_result", tool_use_id: callID, content: err },
            ]),
          )
          emitMetric(sessionID, "tool_failed", { tool_name: toolName })
        }
      }
      return
    }

    if (event.type === "session.diff") {
      const props = event.properties
      if (!props || typeof props !== "object") return
      const sessionID = typeof props.sessionID === "string" ? props.sessionID : ""
      if (!sessionID) return
      const diff = typeof props.diff === "string" ? props.diff : JSON.stringify(props.diff ?? "")
      emitMetric(sessionID, "repo_session_end", { diff })
      return
    }

    if (event.type === "session.idle") {
      const sessionID =
        event.properties && typeof event.properties.sessionID === "string"
          ? event.properties.sessionID
          : ""
      if (!sessionID) return
      emitTrace(sessionID, transcriptPath(sessionID), event.type)
      emitMetric(sessionID, "session_idle")
    }
  },
})
