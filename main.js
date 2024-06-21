import CommandPrompt from "./services/commandPrompt.js";

const commandPrompt = new CommandPrompt();
await commandPrompt.start();

process.exit();
