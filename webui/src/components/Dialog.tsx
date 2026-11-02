import { useEffect } from "react";
import {
  Dialog as ShadcnDialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
  DialogClose,
} from "./ui/dialog";
import type { ReactNode } from "react";

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
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  return (
    <ShadcnDialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent style={{ width, maxWidth: "96vw" }}>
        {(title || subtitle) && (
          <DialogHeader>
            {title && <DialogTitle>{title}</DialogTitle>}
            {subtitle && <DialogDescription>{subtitle}</DialogDescription>}
          </DialogHeader>
        )}
        <div className="dialog-body">{children}</div>
        {footer && <DialogFooter>{footer}</DialogFooter>}
        <DialogClose className="ghost dialog-close" aria-label="Close">
          ✕
        </DialogClose>
      </DialogContent>
    </ShadcnDialog>
  );
}
