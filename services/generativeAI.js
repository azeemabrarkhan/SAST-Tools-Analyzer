import dotenv from "dotenv";
import { GoogleGenerativeAI } from "@google/generative-ai";
import { HarmCategory, HarmBlockThreshold } from "@google/generative-ai";
import { log } from "./logger.js";

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
    const result = await model.generateContent(prompt.trim());
    const response = await result.response;
    const text = response.text();
    return text;
  }

  async chatWithAI(prompt) {
    try {
      const result = await this.chatObject.sendMessage(prompt.trim());
      const response = await result.response;
      const text = await response.text();
      return text;
    } catch (err) {
      console.error(err);
      log(
        `ERROR, in having a response from generative AI for the prompt: ${prompt
          .trim()
          .substring(0, 50)}.... - error trace: ${err}`
      );
    }
  }

  async getSeriesOfResponses(previousData, prompts) {
    const aiResponses = [];
    for (const prompt of prompts) {
      const result = await this.chatWithAI(prompt);
      aiResponses.push(result);
    }
    return { ...previousData, aiResponses };
  }

  async getHistory() {
    return await this.chatObject.getHistory();
  }

  async getReadableHistory() {
    const history = await this.getHistory();
    return history
      .map(
        (textObj) =>
          `${textObj.role === "user" ? "User" : "AI-response"}: ${
            textObj.parts[0].text
          }\n\n`
      )
      .reduce((finalText, currentText) => finalText + currentText, "");
  }
}
