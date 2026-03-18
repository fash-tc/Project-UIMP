'use client';

export default function AIChatPage() {
  return (
    <div className="w-full h-[calc(100vh-4rem)]">
      <iframe
        src="/ai-chat-api/"
        className="w-full h-full border-0"
        title="AI Chat"
        allow="clipboard-write"
      />
    </div>
  );
}
