import { useEffect, useRef, ReactNode } from "react";

interface Props {
  open: boolean;
  title?: string;
  subtitle?: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  width?: string;
}

export default function Dialog({
  open,
  title,
  subtitle,
  onClose,
  children,
  footer,
  width = "min(640px, 96vw)",
}: Props) {
  const overlayRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className="dialog-overlay"
      ref={overlayRef}
      onClick={(e) => {
        if (e.target === overlayRef.current) onClose();
      }}
    >
      <div
        className="dialog"
        style={{ width }}
        role="dialog"
        aria-modal="true"
        aria-labelledby={title ? "dialog-title" : undefined}
      >
        {(title || subtitle) && (
          <div className="dialog-head">
            <div>
              {title && (
                <h2 id="dialog-title" className="dialog-title">
                  {title}
                </h2>
              )}
              {subtitle && <p className="muted dialog-subtitle">{subtitle}</p>}
            </div>
            <button
              type="button"
              className="ghost dialog-close"
              onClick={onClose}
              aria-label="Close"
            >
              ✕
            </button>
          </div>
        )}
        <div className="dialog-body">{children}</div>
        {footer && <div className="dialog-foot">{footer}</div>}
      </div>
    </div>
  );
}