// ─── LLM Provider Interface ──────────────────────────────────────────

export interface LLMProviderConfig {
  /** Model name / deployment (e.g. "gpt-4o", "gpt-4o-mini") */
  model: string;
  /** API endpoint URL (optional — provider default used if omitted) */
  endpoint?: string;
  /** API key (from env var, never stored in config file) */
  apiKey?: string;
  /** Max tokens for the response */
  maxTokens: number;
  /** Request timeout in milliseconds */
  timeoutMs: number;
}

export interface LLMMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface LLMCompletionResult {
  content: string;
  usage?: {
    promptTokens: number;
    completionTokens: number;
  };
}

/**
 * Abstract interface for LLM providers.
 * Implementations should handle authentication and API calls.
 */
export interface LLMProvider {
  /** Human-readable name of the provider */
  readonly name: string;
  /** Complete a chat-style prompt */
  complete(messages: LLMMessage[], config: LLMProviderConfig): Promise<LLMCompletionResult>;
}

// ─── Stub / Mock Provider ────────────────────────────────────────────

/**
 * A stub provider that returns a pre-configured response.
 * Used for testing and when no real provider is configured.
 */
export class StubProvider implements LLMProvider {
  readonly name = "stub";
  private response: string;

  constructor(response: string) {
    this.response = response;
  }

  async complete(_messages: LLMMessage[], _config: LLMProviderConfig): Promise<LLMCompletionResult> {
    return {
      content: this.response,
      usage: { promptTokens: 0, completionTokens: 0 },
    };
  }
}

// ─── OpenAI-compatible Provider ──────────────────────────────────────

/**
 * Generic OpenAI-compatible provider.
 * Works with OpenAI, Azure OpenAI, GitHub Models, and any
 * API that implements the OpenAI chat completions interface.
 */
export class OpenAICompatibleProvider implements LLMProvider {
  readonly name = "openai-compatible";

  async complete(messages: LLMMessage[], config: LLMProviderConfig): Promise<LLMCompletionResult> {
    const endpoint = config.endpoint ?? "https://api.openai.com/v1";
    const url = `${endpoint.replace(/\/+$/, "")}/chat/completions`;

    if (!config.apiKey) {
      throw new Error("LLM API key is required. Set REDTEAM_LLM_KEY env var.");
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), config.timeoutMs);

    try {
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${config.apiKey}`,
        },
        body: JSON.stringify({
          model: config.model,
          messages: messages.map((m) => ({ role: m.role, content: m.content })),
          max_tokens: config.maxTokens,
          temperature: 0.2,
          response_format: { type: "json_object" },
        }),
        signal: controller.signal,
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`LLM API error ${response.status}: ${errorText.slice(0, 200)}`);
      }

      const data = (await response.json()) as {
        choices: Array<{ message: { content: string } }>;
        usage?: { prompt_tokens: number; completion_tokens: number };
      };

      return {
        content: data.choices[0]?.message?.content ?? "",
        usage: data.usage
          ? {
              promptTokens: data.usage.prompt_tokens,
              completionTokens: data.usage.completion_tokens,
            }
          : undefined,
      };
    } finally {
      clearTimeout(timeout);
    }
  }
}
