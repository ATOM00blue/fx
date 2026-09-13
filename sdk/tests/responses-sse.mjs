export function responsesTextEvents(chunks, usage = { input_tokens: 3, output_tokens: 2 }) {
  return [
    ...chunks.map((delta) => ({ type: "response.output_text.delta", delta })),
    {
      type: "response.completed",
      response: {
        id: "resp_sdk",
        status: "completed",
        usage,
      },
    },
  ];
}

export function encodeSse(events) {
  return events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join("");
}

export function responsesTextSse(chunks, usage) {
  return encodeSse(responsesTextEvents(chunks, usage));
}

export function responsesToolCallEvents(id, name, input, outputIndex = 0) {
  const argumentsJson = typeof input === "string" ? input : JSON.stringify(input ?? {});
  return [
    {
      type: "response.output_item.added",
      output_index: outputIndex,
      item: { type: "function_call", call_id: id, name, arguments: "" },
    },
    {
      type: "response.function_call_arguments.done",
      output_index: outputIndex,
      arguments: argumentsJson,
    },
    { type: "response.completed", response: { id: "resp_sdk", status: "completed" } },
  ];
}
