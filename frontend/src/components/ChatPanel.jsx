import React, { useRef } from 'react';
import ChatView from './ChatView';

// Persistent copilot panel sitting between the sidebar and the views. Wraps
// ChatView with a header (collapse toggle + context indicator) and a drag
// handle on its right edge to resize.
export default function ChatPanel({
  collapsed,
  onToggle,
  width,
  onResize,
  contextLabel,
  ...chatProps
}) {
  const panelRef = useRef(null);
  const dragging = useRef(false);

  const startResize = (e) => {
    e.preventDefault();
    dragging.current = true;
    const onMove = (ev) => {
      if (!dragging.current || !panelRef.current) return;
      // Panel is anchored to its left edge; width grows as the cursor moves right.
      const left = panelRef.current.getBoundingClientRect().left;
      const next = Math.min(640, Math.max(300, ev.clientX - left));
      onResize(next);
    };
    const onUp = () => {
      dragging.current = false;
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
  };

  if (collapsed) {
    return (
      <div className="chat-panel collapsed">
        <button className="chat-expand-btn" onClick={onToggle} title="Open PacketIQ AI">
          <span className="chat-expand-icon">💬</span>
          <span className="chat-expand-label">PacketIQ&nbsp;AI</span>
        </button>
      </div>
    );
  }

  return (
    <div className="chat-panel" style={{ width }} ref={panelRef}>
      <div className="chat-resize-handle" onMouseDown={startResize} title="Drag to resize" />
      <div className="chat-panel-header">
        <div className="chat-panel-title">
          <span className="chat-panel-dot" />
          PacketIQ AI
        </div>
        {contextLabel && <div className="chat-context-chip" title="What the AI can see">{contextLabel}</div>}
        <button className="chat-collapse-btn" onClick={onToggle} title="Collapse">‹</button>
      </div>
      <ChatView {...chatProps} />
    </div>
  );
}
