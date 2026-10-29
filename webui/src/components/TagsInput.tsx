import { useMemo, useRef, useState } from "react";

interface TagsInputProps {
  value: string[];
  onChange: (next: string[]) => void;
  suggestions?: string[];      // e.g. terms used by other rules
  placeholder?: string;
  maxLength?: number;
  id?: string;
}

export default function TagsInput({
  value, onChange, suggestions = [], placeholder, maxLength = 100, id,
}: TagsInputProps) {
  const [draft, setDraft] = useState("");
  const [open, setOpen] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  // Suggestions not already selected, filtered by the draft
  const filtered = useMemo(() => {
    const q = draft.trim().toLowerCase();
    return suggestions
      .filter((s) => !value.includes(s))
      .filter((s) => (q ? s.toLowerCase().includes(q) : true))
      .slice(0, 8);
  }, [suggestions, value, draft]);

  function add(raw: string) {
    const term = raw.trim();
    if (!term || value.includes(term) || term.length > maxLength) return;
    onChange([...value, term]);
    setDraft("");
    setOpen(false);
    inputRef.current?.focus();
  }

  function remove(term: string) {
    onChange(value.filter((t) => t !== term));
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault();
      if (filtered.length && draft.trim() && open) add(draft);
      else add(draft);
    } else if (e.key === "Backspace" && !draft && value.length) {
      // Backspace on empty input removes the last chip
      remove(value[value.length - 1]);
    }
  }

  function onPaste(e: React.ClipboardEvent<HTMLInputElement>) {
    const text = e.clipboardData.getData("text");
    if (!/[,;\n]/.test(text)) return;
    e.preventDefault();
    const parts = text.split(/[,;\n]+/).map((s) => s.trim()).filter(Boolean);
    const next = [...value];
    for (const p of parts) {
      if (!next.includes(p) && p.length <= maxLength) next.push(p);
    }
    onChange(next);
  }

  return (
    <div className="tags-input" onClick={() => inputRef.current?.focus()}>
      {value.map((term) => (
        <span key={term} className="tag">
          {term}
          <button
            type="button"
            className="tag-remove"
            aria-label={`Remove ${term}`}
            onClick={(e) => { e.stopPropagation(); remove(term); }}
          >
            ×
          </button>
        </span>
      ))}
      <div className="tags-entry">
        <input
          id={id}
          ref={inputRef}
          value={draft}
          placeholder={value.length ? "" : placeholder}
          maxLength={maxLength}
          onChange={(e) => { setDraft(e.target.value); setOpen(true); }}
          onFocus={() => setOpen(true)}
          onBlur={() => setTimeout(() => setOpen(false), 120)}
          onKeyDown={onKeyDown}
          onPaste={onPaste}
        />
        {open && filtered.length > 0 && (
          <ul className="tags-suggest" role="listbox">
            {filtered.map((s) => (
              <li key={s}>
                <button
                  type="button"
                  role="option"
                  onMouseDown={(e) => e.preventDefault()} // keep focus
                  onClick={() => add(s)}
                >
                  {s}
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}