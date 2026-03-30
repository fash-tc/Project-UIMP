'use client';

export default function AIChatPage() {
  return (
    <div className="flex flex-col h-[calc(100vh-4rem)] w-full">
      <iframe
        src="/ai-chat-api/"
        className="flex-1 w-full border-0"
        allow="clipboard-write; microphone"
        title="AI Chat"
      />
    </div>
  );
}
