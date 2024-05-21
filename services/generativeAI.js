import dotenv from "dotenv";
import { GoogleGenerativeAI } from "@google/generative-ai";
import { HarmCategory, HarmBlockThreshold } from "@google/generative-ai";

dotenv.config();

const genAI = new GoogleGenerativeAI(process.env.GENERATIVE_AI_API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-pro" });
const safetySettings = [
  {
    category: HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
    threshold: HarmBlockThreshold.BLOCK_NONE,
  },
  {
    category: HarmCategory.HARM_CATEGORY_HARASSMENT,
    threshold: HarmBlockThreshold.BLOCK_NONE,
  },
  {
    category: HarmCategory.HARM_CATEGORY_HATE_SPEECH,
    threshold: HarmBlockThreshold.BLOCK_NONE,
  },
  {
    category: HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
    threshold: HarmBlockThreshold.BLOCK_NONE,
  },
];

export default class GenerativeAI {
  maxTokens;
  chatObject;

  constructor(maxTokens) {
    this.maxTokens = maxTokens ? maxTokens : 500;
    this.chatObject = model.startChat({
      history: [],
      generationConfig: {
        maxOutputTokens: this.maxTokens,
      },
      safetySettings,
    });
  }

  resetCurrentChat() {
    this.chatObject = model.startChat({
      history: [],
      generationConfig: {
        maxOutputTokens: this.maxTokens,
      },
      safetySettings,
    });
  }

  async askOneTimeQuery(prompt) {
    const result = await model.generateContent(prompt);
    const response = await result.response;
    const text = response.text();
    return text;
  }

  async chatWithAI(prompt) {
    const result = await this.chatObject.sendMessage(prompt);
    const response = await result.response;
    const text = await response.text();
    return text;
  }

  async getHistory() {
    return await this.chatObject.getHistory();
  }
}
