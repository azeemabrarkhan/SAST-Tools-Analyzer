import dotenv from "dotenv";
import { GoogleGenerativeAI } from "@google/generative-ai";

dotenv.config();

const genAI = new GoogleGenerativeAI(process.env.GENERATIVE_AI_API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-pro" });

export default class GenerativeAI {
  chat;

  constructor(maxTokens) {
    this.chat = model.startChat({
      history: [],
      generationConfig: {
        maxOutputTokens: maxTokens ? maxTokens : 500,
      },
    });
  }

  resetCurrentChat() {
    this.chat = model.startChat({
      history: [],
      generationConfig: {
        maxOutputTokens: maxTokens ? maxTokens : 500,
      },
    });
  }

  async askOneTimeQuery(prompt) {
    const result = await model.generateContent(prompt);
    const response = await result.response;
    const text = response.text();
    return text;
  }

  async chatWithAI(prompt) {
    const result = await chat.sendMessage(prompt);
    const response = await result.response;
    const text = await response.text();
    return text;
  }
}
