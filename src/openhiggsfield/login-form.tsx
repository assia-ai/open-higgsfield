"use client";

import { useActionState } from "react";

import { login, type LoginState } from "@/auth/actions";

import { KeyIcon } from "./icons";

export function LoginForm({ next }: { next: string }) {
  const [state, action, pending] = useActionState<LoginState, FormData>(login, {
    error: null,
    user: "",
  });

  return (
    <main className="ohf-login">
      <form action={action} className="ohf-dialog-panel ohf-keys-panel ohf-login-panel">
        <div className="ohf-keys-head">
          <div>
            <h1 className="ohf-keys-title">Sign in</h1>
            <p className="ohf-keys-copy">This studio is private. Sign in to generate.</p>
          </div>
          <span className="ohf-login-mark" aria-hidden>
            <KeyIcon />
          </span>
        </div>

        <div className="ohf-keys-form">
          <input type="hidden" name="next" value={next} />
          <label className="ohf-field">
            <div className="ohf-field-label">Username</div>
            <input
              className="ohf-input"
              name="user"
              defaultValue={state.user}
              autoComplete="username"
              autoCapitalize="none"
              spellCheck={false}
              required
              autoFocus
            />
          </label>
          <label className="ohf-field">
            <div className="ohf-field-label">Password</div>
            <input
              className="ohf-input"
              name="password"
              type="password"
              autoComplete="current-password"
              required
            />
          </label>

          {state.error && (
            <div className="ohf-alert" role="alert">
              <span className="ohf-alert-text">{state.error}</span>
            </div>
          )}

          <div className="ohf-keys-actions">
            <button type="submit" className="ohf-keys-save" disabled={pending}>
              {pending ? "Signing in…" : "Sign in"}
            </button>
          </div>
        </div>
      </form>
    </main>
  );
}
