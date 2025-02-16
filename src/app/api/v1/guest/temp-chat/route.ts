import { openai } from "@ai-sdk/openai";
import { streamText } from "ai";

export async function POST(req: Request) {
  const { messages } = await req.json();

  const result = await streamText({
    model: openai("gpt-4-turbo"),
    prompt: messages[messages.length - 1].content,
  });

  return result.toDataStreamResponse();
}
